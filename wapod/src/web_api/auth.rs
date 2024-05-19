use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::Request;
use tracing::warn;

pub struct ApiToken {
    value: String,
}

impl ApiToken {
    pub fn new(token: String) -> Self {
        let value = if token.is_empty() {
            warn!("API token is empty. No authorization required.");
            String::new()
        } else {
            format!("Bearer {}", token)
        };
        Self { value }
    }
}

pub struct Authorized;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authorized {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = request
            .rocket()
            .state::<ApiToken>()
            .expect("Token state not available.");
        if token.value.is_empty() {
            return Outcome::Success(Authorized);
        }
        match request.headers().get_one("Authorization") {
            Some(value) => {
                // Check the Bearer token
                if value == token.value {
                    Outcome::Success(Authorized)
                } else {
                    Outcome::Error((Status::Unauthorized, "invalid token"))
                }
            }
            _ => Outcome::Error((Status::Unauthorized, "Authorization header not found")),
        }
    }
}
