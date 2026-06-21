use serde::Deserialize;
use utoipa::ToSchema;
use validator::Validate;

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct SignupRequest {
    #[validate(email, length(max = 254))]
    pub email: String,
    #[validate(length(min = 8, max = 4096))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct TokenRequest {
    #[validate(length(min = 1))]
    pub token: String,
}
