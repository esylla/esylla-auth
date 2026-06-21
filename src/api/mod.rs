//! HTTP layer: routes, the session cookie, and the `CurrentUser` extractor.

use axum::extract::FromRef;
use esylla::utoipa_axum::router::OpenApiRouter;
use esylla::utoipa_axum::routes;

use crate::service::AuthServices;

mod cookie;
mod extract;
mod handlers;
#[cfg(feature = "oauth")]
mod oauth;

pub use extract::CurrentUser;

/// The built-in endpoints. A host can exclude any of these (via
/// [`crate::Auth::without`]) and mount its own handler — e.g. a signup that also
/// captures a nickname — on the public [`AuthServices`] building blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthRoute {
    Signup,
    VerifyEmail,
    Login,
    Logout,
    ForgotPassword,
    ResetPassword,
    ChangePassword,
}

impl AuthRoute {
    pub const ALL: [AuthRoute; 7] = [
        AuthRoute::Signup,
        AuthRoute::VerifyEmail,
        AuthRoute::Login,
        AuthRoute::Logout,
        AuthRoute::ForgotPassword,
        AuthRoute::ResetPassword,
        AuthRoute::ChangePassword,
    ];
}

pub(crate) fn routes<S>(enabled: &[AuthRoute]) -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    AuthServices: FromRef<S>,
{
    let mut router = OpenApiRouter::new();
    for route in enabled {
        router = match route {
            AuthRoute::Signup => router.routes(routes!(handlers::signup)),
            AuthRoute::VerifyEmail => router.routes(routes!(handlers::verify_email)),
            AuthRoute::Login => router.routes(routes!(handlers::login)),
            AuthRoute::Logout => router.routes(routes!(handlers::logout)),
            AuthRoute::ForgotPassword => router.routes(routes!(handlers::forgot_password)),
            AuthRoute::ResetPassword => router.routes(routes!(handlers::reset_password)),
            AuthRoute::ChangePassword => router.routes(routes!(handlers::change_password)),
        };
    }

    #[cfg(feature = "oauth")]
    {
        router = router
            .routes(routes!(oauth::authorize))
            .routes(routes!(oauth::callback));
    }

    router
}
