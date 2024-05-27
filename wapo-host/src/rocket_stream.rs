use std::pin::Pin;

use anyhow::{anyhow, Result};
use rocket::{
    data::{ByteUnit, IoHandler, IoStream},
    http::Status,
    request::{FromRequest, Outcome},
    response::Responder,
    Data, Request,
};
use tokio::{
    io::{split, AsyncRead, AsyncWriteExt, DuplexStream},
    sync::oneshot::channel as oneshot_channel,
};
use tracing::{debug, error};
use wapo_env::messages::{HttpHead, HttpResponseHead};

use crate::{
    service::{Command, CommandSender},
    IncomingHttpRequest,
};

pub struct RequestInfo {
    method: String,
    host: String,
    query: String,
    headers: Vec<(String, String)>,
}

#[pin_project::pin_project]
pub struct StreamResponse {
    head: HttpResponseHead,
    #[pin]
    io_stream: DuplexStream,
    guard: Option<Box<dyn Send + Sync>>,
}

impl StreamResponse {
    pub fn new(head: HttpResponseHead, io_stream: DuplexStream) -> Self {
        Self {
            head,
            io_stream,
            guard: None,
        }
    }

    pub fn new_with_guard<T: Send + Sync + 'static>(
        head: HttpResponseHead,
        io_stream: DuplexStream,
        guard: T,
    ) -> Self {
        Self {
            head,
            io_stream,
            guard: Some(Box::new(guard)),
        }
    }
}

#[rocket::async_trait]
impl IoHandler for StreamResponse {
    async fn io(self: Pin<Box<Self>>, io: IoStream) -> std::io::Result<()> {
        let Self {
            io_stream,
            guard: _guard,
            head: _,
        } = *Pin::into_inner(self);
        let (mut server_reader, mut server_writer) = split(io_stream);
        let (mut client_reader, mut client_writer) = split(io);
        let c2s_task = async {
            let result = tokio::io::copy(&mut client_reader, &mut server_writer).await;
            debug!(target: "wapo", "copy from client to server done");
            server_writer.shutdown().await.ok();
            result
        };
        let s2c_task = async {
            let result = tokio::io::copy(&mut server_reader, &mut client_writer).await;
            debug!(target: "wapo", "copy from server to client done");
            client_writer.shutdown().await.ok();
            result
        };
        let (res_c2s, res_s2c) = tokio::join! {
            c2s_task,
            s2c_task,
        };
        if let Err(err) = res_c2s {
            error!(target: "wapo", "failed to copy from client to server: {err}");
            return Err(err);
        }
        if let Err(err) = res_s2c {
            error!(target: "wapo", "failed to copy from server to client: {err}");
            return Err(err);
        }
        Ok(())
    }
}

impl<'r> Responder<'r, 'r> for StreamResponse {
    fn respond_to(mut self, _req: &'r Request<'_>) -> rocket::response::Result<'r> {
        let mut builder = rocket::response::Response::build();
        self.head
            .headers
            .retain(|(name, _)| name.to_lowercase() != "set-cookie");
        if Status::new(self.head.status) == Status::SwitchingProtocols {
            // As Rocket requires to not set status to 101 and do not set headers 'Connection', 'Upgrade',
            // we need to remove them from the response header.
            builder.status(Status::ServiceUnavailable);
            let mut protocol = String::new();
            for (name, value) in self.head.headers.drain(..) {
                let name = name.to_lowercase();
                if name == "upgrade" {
                    protocol = value.to_string();
                }
                if name != "connection" && name != "upgrade" {
                    builder.raw_header_adjoin(name, value);
                }
            }
            builder.upgrade(protocol, self);
            builder.streamed_body(&[] as &[u8]);
        } else {
            builder.status(Status::new(self.head.status));
            for (name, value) in std::mem::take(&mut self.head.headers) {
                builder.raw_header_adjoin(name, value);
            }
            builder.streamed_body(self);
        }
        Ok(builder.finalize())
    }
}

impl AsyncRead for StreamResponse {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().io_stream.poll_read(cx, buf)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequestInfo {
    type Error = &'static str;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let method = req.method().to_string();
        let uri = req.uri();
        let query = uri.query().map(|s| s.to_string()).unwrap_or_default();
        let host = req.host().map(|s| s.to_string()).unwrap_or_default();
        let headers = req
            .headers()
            .iter()
            .filter_map(|header| {
                if header.name.as_uncased_str() == "cookie" {
                    None
                } else {
                    Some((header.name.to_string(), header.value.to_string()))
                }
            })
            .collect();
        Outcome::Success(Self {
            method,
            host,
            query,
            headers,
        })
    }
}

impl RequestInfo {
    fn into_head(self, path: &str) -> HttpHead {
        let Self {
            method,
            host,
            query,
            headers,
        } = self;
        let mut url = format!("http://{}/{}", host, path);
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query);
        }
        HttpHead {
            method,
            url,
            headers,
        }
    }
}

fn is_upgrade_request(req: &RequestInfo) -> bool {
    req.headers
        .iter()
        .find_map(|(name, value)| {
            if name.to_lowercase() == "connection" {
                Some(value.to_lowercase() == "upgrade")
            } else {
                None
            }
        })
        .unwrap_or(false)
}

pub async fn connect<T: Send + Sync + 'static>(
    head: RequestInfo,
    path: &str,
    body: Option<Data<'_>>,
    command_tx: CommandSender,
    guard: T,
) -> Result<StreamResponse> {
    let is_upgrade = is_upgrade_request(&head);
    let (response_tx, response_rx) = oneshot_channel();
    let (mut stream0, stream1) = tokio::io::duplex(1024);
    let command = Command::HttpRequest(IncomingHttpRequest {
        head: head.into_head(path),
        body_stream: stream1,
        response_tx,
    });
    command_tx
        .send(command)
        .await
        .or(Err(anyhow!("Command channel closed")))?;
    if !is_upgrade {
        // If it is a vanilla HTTP request, we need to send the body.
        if let Some(body) = body {
            let data_stream = body.open(ByteUnit::max_value());
            let stream0 = &mut stream0;
            let result: Result<()> = async move {
                data_stream.stream_to(&mut *stream0).await?;
                stream0
                    .shutdown()
                    .await
                    .or(Err(anyhow!("Stream shutdown error")))?;
                Ok(())
            }
            .await;
            if let Err(err) = result {
                error!(target: "wapo", "failed to pipe the body: {err:?}");
            }
        }
    }
    let resposne = response_rx
        .await
        .map_err(|_| anyhow!("Response channel closed"))??;
    Ok(StreamResponse::new_with_guard(resposne, stream0, guard))
}
