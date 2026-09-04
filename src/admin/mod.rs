//! Admin HTTP API and dashboard.

pub mod http;
pub mod routes;

use std::sync::Arc;

use crate::state::AppState;

/// Serves the admin API until shutdown. Returns immediately when disabled.
pub async fn run(state: Arc<AppState>) -> std::io::Result<()> {
    if !state.config().admin.enabled {
        tracing::info!("admin API is disabled");
        return Ok(());
    }
    http::serve(state, routes::handle).await
}
