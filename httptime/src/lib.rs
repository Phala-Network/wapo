use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

/// Get the current time from an HTTP server where the time is in the `Date` header in the response.
pub async fn get_time(url: &str, timeout: Duration) -> Result<SystemTime> {
    let headers = runtime::time::timeout(timeout, runtime::head(url))
        .await
        .context("request timeout")?
        .context("failed to fetch headers")?;
    let value = headers
        .get("date")
        .context("no date header")?
        .to_str()
        .context("invalid date header")?;
    httpdate::parse_http_date(value).context("failed to parse date")
}

#[cfg(not(target_os = "wasi"))]
mod runtime {
    use anyhow::Result;
    use hyper::HeaderMap;

    pub use tokio::time;

    pub async fn head(url: &str) -> Result<HeaderMap> {
        let headers = reqwest::Client::new()
            .head(url)
            .send()
            .await?
            .error_for_status()?
            .headers()
            .clone();
        Ok(headers)
    }
}

#[cfg(target_os = "wasi")]
mod runtime {
    use anyhow::{bail, Context, Result};
    use http_body_util::Empty;
    use hyper::{body::Bytes, client::conn::http1::handshake, HeaderMap, Request};
    use wapo::{hyper_rt::HyperTokioIo, net::TcpStream};

    pub use wapo::time;

    pub async fn head(url: &str) -> Result<HeaderMap> {
        let url = url.parse::<hyper::Uri>()?;
        let host = url.host().expect("uri has no host");
        let is_tls = url.scheme_str().map_or(false, |s| s == "https");
        let port = url.port_u16().unwrap_or(if is_tls { 443 } else { 80 });
        let stream = TcpStream::connect(host, port, is_tls).await?;
        let io = HyperTokioIo::new(stream);

        let authority = url.authority().context("uri has no authority")?;

        let (mut sender, conn) = handshake(io).await?;
        wapo::spawn(async move {
            _ = conn.await;
        });

        let path = url.path();
        let req = Request::builder()
            .uri(path)
            .method(hyper::Method::HEAD)
            .header(hyper::header::HOST, authority.as_str())
            .body(Empty::<Bytes>::new())?;
        let res = sender.send_request(req).await.context("request failed")?;
        if !res.status().is_success() {
            bail!("Request failed: {}", res.status());
        }
        Ok(res.headers().clone())
    }
}

#[cfg(test)]
mod test {
    use futures::{stream::FuturesUnordered, StreamExt};

    use super::*;

    #[tokio::test]
    async fn test_get_time() {
        let servers = [
            "https://www.cloudflare.com",
            "https://www.apple.com",
            "https://www.baidu.com",
            "https://kernel.org/",
        ];

        let mut futures = FuturesUnordered::new();
        for server in &servers {
            futures.push({
                let url = server.to_string();
                async { (get_time(&url, Duration::from_secs(2)).await, url) }
            });
        }
        loop {
            let Some((result, url)) = futures.next().await else {
                break;
            };
            println!("{:?} from {url}", result);
        }
    }
}
