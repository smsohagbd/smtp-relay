//! Inbound SMTP listener.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::smtp::session::Session;
use crate::state::AppState;
use crate::util::Cidr;

/// Binds the listener and serves connections until shutdown.
pub async fn run(state: Arc<AppState>) -> std::io::Result<()> {
    let config = state.config();
    let address: SocketAddr = config.server.bind_address.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "server.bind_address `{}` is not a valid socket address",
                config.server.bind_address
            ),
        )
    })?;

    let listener = TcpListener::bind(address).await.map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("could not bind {address}: {error}"),
        )
    })?;

    let limit = config.server.max_connections.max(1);
    let permits = Arc::new(Semaphore::new(limit));
    let mut shutdown = state.subscribe_shutdown();

    tracing::info!(
        %address,
        hostname = %config.server.hostname,
        max_connections = limit,
        max_message_size_mb = config.server.max_message_size_mb,
        submission_mode = config.server.submission_mode.as_str(),
        auth_required = config.server.require_auth,
        "SMTP listener ready"
    );

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("SMTP listener stopping");
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        handle_accepted(&state, &permits, stream, peer).await;
                    }
                    Err(error) => {
                        // A single failed accept (e.g. EMFILE) must not kill
                        // the listener; back off briefly and continue.
                        tracing::warn!(%error, "accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_accepted(
    state: &Arc<AppState>,
    permits: &Arc<Semaphore>,
    mut stream: TcpStream,
    peer: SocketAddr,
) {
    let config = state.config();

    // Re-read the allow-list on every connection so a hot reload takes effect
    // immediately.
    if !is_allowed(&config.inbound_networks(), peer) {
        state
            .metrics
            .inc(&state.metrics.counters.connections_rejected);
        tracing::warn!(%peer, "refused connection: source is not in server.allowed_networks");
        let _ = stream
            .write_all(b"554 5.7.1 access denied\r\n")
            .await;
        let _ = stream.shutdown().await;
        return;
    }

    let permit = match Arc::clone(permits).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            state
                .metrics
                .inc(&state.metrics.counters.connections_rejected);
            tracing::warn!(
                %peer,
                limit = config.server.max_connections,
                "refused connection: at server.max_connections"
            );
            let _ = stream
                .write_all(b"421 4.3.2 too many concurrent connections, try again later\r\n")
                .await;
            let _ = stream.shutdown().await;
            return;
        }
    };

    // Replies are small and latency-sensitive; Nagle would add needless delay
    // to the command/response ping-pong.
    if let Err(error) = stream.set_nodelay(true) {
        tracing::debug!(%peer, %error, "could not set TCP_NODELAY");
    }

    state.metrics.connection_opened();
    tracing::debug!(%peer, "connection accepted");

    let session_state = Arc::clone(state);
    tokio::spawn(async move {
        // The permit is released when the session task ends, however it ends.
        let _permit = permit;
        Session::new(session_state, stream, peer).run().await;
    });
}

/// Empty allow-list means "accept from anywhere".
fn is_allowed(networks: &[Cidr], peer: SocketAddr) -> bool {
    networks.is_empty() || networks.iter().any(|network| network.contains(peer.ip()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(address: &str) -> SocketAddr {
        address.parse().unwrap()
    }

    #[test]
    fn empty_allow_list_accepts_everything() {
        assert!(is_allowed(&[], peer("203.0.113.9:1234")));
    }

    #[test]
    fn allow_list_filters_by_network() {
        let networks = vec![
            Cidr::parse("127.0.0.0/8").unwrap(),
            Cidr::parse("10.20.0.0/16").unwrap(),
        ];
        assert!(is_allowed(&networks, peer("127.0.0.1:25")));
        assert!(is_allowed(&networks, peer("10.20.30.40:25")));
        assert!(!is_allowed(&networks, peer("10.21.0.1:25")));
        assert!(!is_allowed(&networks, peer("203.0.113.9:25")));
    }

    #[test]
    fn dual_stack_clients_match_ipv4_rules() {
        let networks = vec![Cidr::parse("127.0.0.0/8").unwrap()];
        assert!(is_allowed(&networks, peer("[::ffff:127.0.0.1]:25")));
    }
}
