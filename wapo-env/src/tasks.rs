use core::panic;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Poll, Waker};

use futures::{channel::oneshot, pin_mut};
use log::trace;

use super::*;

extern "Rust" {
    fn wapo_main_future() -> Pin<Box<dyn Future<Output = ()>>>;
}

type TaskFuture = Pin<Box<dyn Future<Output = ()>>>;
/// When a task exited, the task future will be dropped, and it's space in this vector would be
/// set to None in order to reuse it's id in the future.
type Tasks = Vec<Option<TaskFuture>>;

thread_local! {
    /// The id of the current polling task. Would be passed to each ocall.
    static CURRENT_TASK: std::cell::Cell<i32>  = Default::default();
    /// All async tasks in the wapo guest.
    static TASKS: RefCell<Tasks> = {
        std::panic::set_hook(Box::new(|info| {
            log::error!("{}", info);
        }));
        RefCell::new(vec![Some(unsafe { wapo_main_future() })])
    };
    /// New spawned tasks are pushed to this queue. Since tasks are always spawned from inside a
    /// running task which borrowing the TASKS, it can not be immediately pushed to the TASKS.
    static SPAWNING_TASKS: RefCell<Vec<(usize, TaskFuture)>> = const { RefCell::new(vec![]) };
    /// Wakers might being referenced by the wapo host runtime.
    ///
    /// When a ocall polling some resource, we can not pass the waker to the host runtime,
    /// because they are in different memory space and in different rust code compilation space.
    /// So when we poll into the host runtime, we cache the waker in WAKERS, and pass the index,
    /// which called waker_id, into the host runtime. And then before each guest polling, the
    /// guest runtime ask the host runtime to see which waker is awaken or dropped in the host
    /// runtime to deside to awake or drop the waker from this Vec.
    static WAKERS: RefCell<Vec<Option<Waker>>> = const { RefCell::new(vec![]) };

    /// The released waker ids that are cached and can be reused.
    static CACHED_WAKER_IDS: RefCell<VecDeque<i32>> = const { RefCell::new(VecDeque::new()) };
}

const MAX_CACHE_WAKER_IDS: usize = 1024;

fn maybe_cache_waker_id(waker_id: i32) {
    CACHED_WAKER_IDS.with(|ids| {
        let mut ids = ids.borrow_mut();
        if ids.len() < MAX_CACHE_WAKER_IDS {
            ids.push_back(waker_id);
        }
    });
}

fn get_free_waker_id() -> Option<i32> {
    CACHED_WAKER_IDS.with(|ids| {
        let mut ids = ids.borrow_mut();
        if ids.len() == 0 {
            WAKERS.with(|wakers| {
                for (id, waker_ref) in wakers.borrow().iter().enumerate() {
                    if waker_ref.is_none() {
                        ids.push_back(id as i32);
                        if ids.len() >= MAX_CACHE_WAKER_IDS {
                            break;
                        }
                    }
                }
            });
        }
        ids.pop_front()
    })
}

pub fn intern_waker(waker: task::Waker) -> i32 {
    let id = intern_waker_impl(waker);
    trace!("intern waker: {id}");
    id
}

fn intern_waker_impl(waker: task::Waker) -> i32 {
    const MAX_N_WAKERS: usize = (i32::MAX / 2) as usize;
    let free_slot = get_free_waker_id();
    WAKERS.with(|wakers| {
        let mut wakers = wakers.borrow_mut();
        if let Some(id) = free_slot {
            wakers[id as usize] = Some(waker);
            return id;
        }
        if wakers.len() < MAX_N_WAKERS {
            wakers.push(Some(waker));
            wakers.len() as i32 - 1
        } else {
            panic!("Too many wakers");
        }
    })
}

fn wake_waker(waker_id: i32) {
    WAKERS.with(|wakers| {
        let wakers = wakers.borrow();
        if let Some(Some(waker)) = wakers.get(waker_id as usize) {
            trace!("wake waker: {waker_id}");
            waker.wake_by_ref();
        }
    });
}

fn drop_waker(waker_id: i32) {
    WAKERS.with(|wakers| {
        let mut wakers = wakers.borrow_mut();
        if let Some(waker) = wakers.get_mut(waker_id as usize) {
            *waker = None;
            maybe_cache_waker_id(waker_id);
        }
    });
}

pub struct JoinHandle<T>(oneshot::Receiver<T>);

/// The task is dropped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Canceled;

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, Canceled>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let inner = &mut this.0;
        pin_mut!(inner);
        match inner.poll(cx) {
            Poll::Ready(x) => Poll::Ready(x.map_err(|_: oneshot::Canceled| Canceled)),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub fn spawn<T: 'static>(fut: impl Future<Output = T> + 'static) -> JoinHandle<T> {
    spawn_named("unnamed", fut)
}

pub fn spawn_named<T: 'static>(
    name: &str,
    fut: impl Future<Output = T> + 'static,
) -> JoinHandle<T> {
    static GLOBAL_TASK_SN: AtomicUsize = AtomicUsize::new(0);
    let (tx, rx) = oneshot::channel();
    let gsn = GLOBAL_TASK_SN.fetch_add(1, Ordering::Relaxed);
    trace!("[gsn={gsn}] spawn task <{name}>");
    SPAWNING_TASKS.with(move |tasks| {
        (*tasks).borrow_mut().push((
            gsn,
            Box::pin(async move {
                trace!("[gsn={gsn}] task started");
                scopeguard::defer! {
                    trace!("[gsn={gsn}] task exited");
                }
                let _ = tx.send(fut.await);
            }),
        ))
    });
    JoinHandle(rx)
}

fn start_task(gsn: usize, tasks: &mut Tasks, task: TaskFuture) {
    const MAX_N_TASKS: usize = (i32::MAX / 2) as _;

    trace!("[gsn={gsn}] start task");

    for (task_id, task_ref) in tasks.iter_mut().enumerate().skip(1) {
        if task_ref.is_none() {
            *task_ref = Some(task);
            ocall::mark_task_ready(task_id as _).expect("mark task ready failed");
            trace!("[gsn={gsn}] started task, reuse id {task_id}");
            return;
        }
    }

    if tasks.len() < MAX_N_TASKS {
        let task_id = tasks.len();
        trace!("[gsn={gsn}] started task, new id {task_id}");
        tasks.push(Some(task));
        ocall::mark_task_ready(task_id as _).expect("mark task ready failed");
        return;
    }

    panic!("Spawn task failed, Max number of tasks reached");
}

fn start_spawned_tasks(tasks: &mut Tasks) {
    SPAWNING_TASKS.with(|spowned_tasks| {
        for (gsn, task) in spowned_tasks.borrow_mut().drain(..) {
            start_task(gsn, tasks, task);
        }
    });
}

pub(crate) fn current_task() -> i32 {
    CURRENT_TASK.with(|id| id.get())
}

fn set_current_task(task_id: i32) {
    CURRENT_TASK.with(|id| id.set(task_id))
}

fn poll_with_guest_context<F>(f: Pin<&mut F>) -> task::Poll<F::Output>
where
    F: Future + ?Sized,
{
    fn raw_waker(task_id: i32) -> task::RawWaker {
        task::RawWaker::new(
            task_id as _,
            &task::RawWakerVTable::new(
                |data| raw_waker(data as _),
                |data| {
                    let task_id = data as _;
                    ocall::mark_task_ready(task_id).expect("mark task ready failed");
                },
                |data| {
                    let task_id = data as _;
                    ocall::mark_task_ready(task_id).expect("mark task ready failed");
                },
                |_| (),
            ),
        )
    }
    let waker = unsafe { task::Waker::from_raw(raw_waker(current_task())) };
    let mut context = task::Context::from_waker(&waker);
    f.poll(&mut context)
}

pub fn wapo_poll() -> i32 {
    use task::Poll::*;

    fn poll() -> task::Poll<()> {
        {
            let wakers = ocall::awake_wakers().expect("failed to get awake wakers");
            trace!("awake wakers: {wakers:?}");

            for waker_id in wakers {
                if waker_id >= 0 {
                    wake_waker(waker_id);
                } else {
                    drop_waker(-1 - waker_id);
                }
            }

            let next_ready_task = ocall::next_ready_task();
            trace!("next ready task: {next_ready_task:?}");
            let task_id = match next_ready_task {
                Ok(id) => id as usize,
                Err(OcallError::NotFound) => return task::Poll::Pending,
                Err(err) => panic!("Error occured: {:?}", err),
            };
            let exited = TASKS.with(|tasks| -> Option<bool> {
                let exited = {
                    let mut tasks = tasks.borrow_mut();
                    let task = tasks.get_mut(task_id)?.as_mut()?;
                    set_current_task(task_id as _);
                    let ret = poll_with_guest_context(task.as_mut());
                    trace!("poll task {task_id}: {ret:?}");
                    match ret {
                        Pending => (),
                        Ready(()) => {
                            tasks[task_id] = None;
                        }
                    }
                    tasks[0].is_none()
                };
                if !exited {
                    start_spawned_tasks(&mut tasks.borrow_mut());
                }
                Some(exited)
            });
            if let Some(true) = exited {
                return task::Poll::Ready(());
            }
        }
        task::Poll::Pending
    }
    match poll() {
        Ready(()) => 1,
        Pending => 0,
    }
}
