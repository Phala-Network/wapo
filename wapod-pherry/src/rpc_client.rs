use reqwest::Client;
use wapod_rpc::prpc::client::{Error, RequestClient};
use wapod_rpc::prpc::operation_client::OperationClient;
use wapod_rpc::prpc::server::ProtoError;
use wapod_rpc::prpc::user_client::UserClient;
use wapod_rpc::prpc::Message as _;

#[derive(Clone)]
pub struct WorkerClient {
    base_url: String,
    token: String,
    http_client: Client,
}

impl WorkerClient {
    pub fn new(base_url: String, token: String) -> Self {
        Self {
            token,
            base_url,
            http_client: Client::new(),
        }
    }

    pub fn operation(&self) -> OperationClient<Self> {
        OperationClient::new(self.clone())
    }

    pub fn user(&self) -> UserClient<Self> {
        UserClient::new(self.clone())
    }
}

impl RequestClient for WorkerClient {
    async fn request(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, Error> {
        let base_url = self.base_url.trim_end_matches('/');
        let url = format!("{}/prpc/{}", base_url, path);
        let request_builder = self.http_client.post(url);
        let request_builder = if self.token.is_empty() {
            request_builder
        } else {
            request_builder.bearer_auth(&self.token)
        };
        let response = request_builder
            .body(body)
            .send()
            .await
            .map_err(|err| Error::RpcError(err.to_string()))?;
        if !response.status().is_success() {
            let error = Error::RpcError(format!("HTTP error: {}", response.status()));
            if response.status().as_u16() == 400 {
                let Ok(body) = response.bytes().await else {
                    return Err(error);
                };
                let proto_error = ProtoError::decode(body).or(Err(error))?;
                return Err(Error::ServerError(proto_error));
            }
            return Err(error);
        }
        let body = response
            .bytes()
            .await
            .map_err(|err| Error::RpcError(err.to_string()))?;
        Ok(body.into())
    }
}
