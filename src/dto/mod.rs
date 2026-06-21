//! Request DTOs, grouped to mirror the service modules.

mod login;
mod password;
mod signup;

pub use login::LoginRequest;
pub use password::{ChangePasswordRequest, ForgotPasswordRequest, ResetPasswordRequest};
pub use signup::{SignupRequest, TokenRequest};
