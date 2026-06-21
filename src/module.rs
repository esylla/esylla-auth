//! The pluggable module: `.module(Auth::new())` mounts the auth routes and
//! contributes its migrations.

use axum::extract::FromRef;
use esylla::Module;
use esylla::utoipa_axum::router::OpenApiRouter;
use sea_orm_migration::MigrationTrait;

use crate::api::{self, AuthRoute};
use crate::migration;
use crate::service::AuthServices;

pub struct Auth {
    routes: Vec<AuthRoute>,
}

impl Auth {
    /// Mount every built-in route.
    pub fn new() -> Self {
        Auth {
            routes: AuthRoute::ALL.to_vec(),
        }
    }

    /// Mount only the listed routes.
    pub fn only(routes: &[AuthRoute]) -> Self {
        Auth {
            routes: routes.to_vec(),
        }
    }

    /// Mount every route except the listed ones — useful when replacing an
    /// endpoint with a custom handler built on [`AuthServices`].
    pub fn without(mut self, exclude: &[AuthRoute]) -> Self {
        self.routes.retain(|route| !exclude.contains(route));
        self
    }
}

impl Default for Auth {
    fn default() -> Self {
        Auth::new()
    }
}

impl<S> Module<S> for Auth
where
    S: Clone + Send + Sync + 'static,
    AuthServices: FromRef<S>,
{
    fn name(&self) -> &'static str {
        "auth"
    }

    fn routes(&self) -> OpenApiRouter<S> {
        api::routes::<S>(&self.routes)
    }

    fn migrations(&self) -> Vec<Box<dyn MigrationTrait>> {
        migration::migrations()
    }
}
