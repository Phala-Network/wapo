use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{bail, Result};
use cid::Cid;
use reqwest::Client as HttpClient;
use tokio::{io::AsyncWriteExt as _, sync::broadcast, time::timeout};
use tracing::{error, info};

struct IpfsDownloaderState {
    pending: BTreeSet<String>,
    downloading: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub enum Event {
    Downloaded { cid: String },
}

#[derive(Debug, Clone, Copy)]
pub enum ResState {
    Downloading,
    Downloaded,
    NotFound,
}

pub struct Config {
    base_url: String,
    http_client: HttpClient,
    data_dir: PathBuf,
    max_downloading: usize,
    max_pending: usize,
    max_file_size: usize,
    max_download_time: Duration,
    notify: broadcast::Sender<Event>,
}

pub struct IpfsDownloader {
    config: Arc<Config>,
    state: Arc<Mutex<IpfsDownloaderState>>,
}

impl Clone for IpfsDownloader {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: self.state.clone(),
        }
    }
}

impl IpfsDownloader {
    pub fn new(base_url: String, data_dir: impl AsRef<Path>) -> Self {
        let todo = "download size limit and cleanup unused files";
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            config: Arc::new(Config {
                base_url,
                http_client: HttpClient::builder()
                    .connect_timeout(Duration::from_secs(30))
                    .build()
                    .expect("failed to create http client"),
                data_dir: data_dir.as_ref().to_path_buf(),
                max_downloading: 10,
                max_pending: 10000,
                max_file_size: 1024 * 1024 * 50,
                max_download_time: Duration::from_secs(600),
                notify: broadcast::channel(1).0,
            }),
            state: Arc::new(Mutex::new(IpfsDownloaderState {
                pending: BTreeSet::new(),
                downloading: BTreeSet::new(),
            })),
        }
    }

    fn path_of(&self, cid: &str) -> PathBuf {
        self.config.data_dir.join(cid)
    }

    fn tmp_path_of(&self, cid: &str) -> PathBuf {
        self.config.data_dir.join(format!("{}.tmp", cid))
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<Event> {
        self.config.notify.subscribe()
    }

    pub fn exists(&self, cid: &Cid) -> bool {
        self.path_of(&cid.to_string()).exists()
    }

    pub fn state_of(&self, cid: &Cid) -> ResState {
        let cid_str = cid.to_string();
        let state = self.state.lock().unwrap();
        if state.downloading.contains(&cid_str) || state.pending.contains(&cid_str) {
            ResState::Downloading
        } else if self.exists(cid) {
            ResState::Downloaded
        } else {
            ResState::NotFound
        }
    }

    pub fn download(&self, cid: &Cid, force: bool) -> Result<bool> {
        if !force && self.exists(cid) {
            return Ok(true);
        }
        let cid_str = cid.to_string();
        let mut state = self.state.lock().unwrap();

        if state.downloading.contains(&cid_str) || state.pending.contains(&cid_str) {
            info!("already downloading {cid_str}");
            return Ok(false);
        }
        if state.downloading.len() < self.config.max_downloading {
            state.downloading.insert(cid_str.clone());
            info!("downloading {cid_str}");
            let todo = "cancel task if the downloader is dropped";
            tokio::spawn(self.clone().download_task(cid_str));
            return Ok(false);
        } else if state.pending.len() < self.config.max_pending {
            state.pending.insert(cid_str.clone());
            info!("queued {cid_str}");
            return Ok(false);
        } else {
            bail!("download queue full, failed to download {cid_str}");
        }
    }

    pub async fn read(&self, cid: &Cid) -> Result<Option<Vec<u8>>> {
        let path = self.path_of(&cid.to_string());
        let data = match tokio::fs::read(path).await {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        Ok(Some(data))
    }

    pub async fn read_or_download(&self, cid: &Cid) -> Result<Vec<u8>> {
        let mut rx = self.subscribe_events();
        match self.read(cid).await {
            Ok(Some(data)) => return Ok(data),
            Ok(None) => {}
            Err(err) => return Err(err),
        }
        self.download(cid, true)?;
        loop {
            let event = rx.recv().await?;
            match event {
                Event::Downloaded {
                    cid: downloaded_cid,
                } => {
                    if downloaded_cid == cid.to_string() {
                        return self
                            .read(cid)
                            .await?
                            .ok_or_else(|| anyhow::anyhow!("downloaded file not found: {cid}"));
                    }
                }
            }
        }
    }

    async fn download_task(self, mut cid_str: String) {
        loop {
            let tmp_file = self.tmp_path_of(&cid_str);
            let url = format!("{}/{}", self.config.base_url, cid_str);
            info!("downloading {cid_str} from {url}");
            let result: Result<Result<_>, _> = timeout(self.config.max_download_time, async {
                let mut output_io = tokio::fs::File::create(&tmp_file).await?;
                let mut response = self
                    .config
                    .http_client
                    .get(url)
                    .send()
                    .await?
                    .error_for_status()?;
                let mut size = 0;
                while let Some(chunk) = response.chunk().await? {
                    size += chunk.len();
                    if size > self.config.max_file_size {
                        bail!("file too large");
                    }
                    output_io.write_all(&chunk).await?;
                }
                Ok(())
            })
            .await;
            match result {
                Ok(Ok(_)) => {
                    info!("downloaded {cid_str}");
                    if let Err(err) = std::fs::rename(&tmp_file, self.path_of(&cid_str)) {
                        error!("failed to rename tmp file: {err:?}");
                    }
                }
                Ok(Err(err)) => {
                    error!("download {cid_str} failed: {err}");
                    let _ = std::fs::remove_file(&tmp_file);
                }
                Err(_) => {
                    error!("download {cid_str} timeout");
                    let _ = std::fs::remove_file(&tmp_file);
                }
            }
            let mut state = self.state.lock().unwrap();
            state.downloading.remove(&cid_str);
            self.config
                .notify
                .send(Event::Downloaded {
                    cid: cid_str.clone(),
                })
                .ok();
            if let Some(next_cid) = state.pending.pop_first() {
                state.downloading.insert(next_cid.clone());
                cid_str = next_cid;
                continue;
            }
            break;
        }
    }
}
