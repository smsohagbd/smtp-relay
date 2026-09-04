//! Relay selection strategies.
//!
//! Selection runs in three stages, most specific first:
//!
//! 1. **Domain overrides** - a recipient domain pinned to specific relays.
//! 2. **Stickiness** - a stable hash so a given sender or recipient domain
//!    keeps the same relay identity across a campaign.
//! 3. **Strategy** - round-robin, smooth weighted, least-used or failover.
//!
//! Only eligible relays are ever considered, and relays already tried for this
//! message are excluded so a retry lands somewhere new.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::config::{DomainOverride, StickyMode, Strategy};
use crate::relay::pool::{Pool, RelayRuntime};
use crate::util::address_domain;

/// What the router needs to know about the message being routed.
#[derive(Debug, Clone, Copy)]
pub struct RouteRequest<'a> {
    /// Original `From` address, used for sender stickiness.
    pub sender: &'a str,
    /// Envelope recipients; the first one drives domain rules.
    pub recipients: &'a [String],
    /// Relay ids already attempted for this message.
    pub exclude: &'a [String],
}

/// The chosen relay and the rule that chose it.
#[derive(Clone)]
pub struct Route {
    pub relay: Arc<RelayRuntime>,
    pub reason: &'static str,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("relay", &self.relay.id())
            .field("reason", &self.reason)
            .finish()
    }
}

/// Why no relay could be chosen. Carries enough detail for an operator to fix
/// the cause without reading the code.
#[derive(Debug, Clone)]
pub struct NoRouteAvailable {
    pub message: String,
}

impl std::fmt::Display for NoRouteAvailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Picks the relay that should carry this message.
pub fn select(pool: &Pool, request: &RouteRequest<'_>) -> Result<Route, NoRouteAvailable> {
    if pool.is_empty() {
        return Err(NoRouteAvailable {
            message: "no relays are configured".to_string(),
        });
    }

    let mut candidates: Vec<usize> = pool
        .relays()
        .iter()
        .enumerate()
        .filter(|(_, relay)| relay.is_eligible())
        .filter(|(_, relay)| !request.exclude.iter().any(|id| id == relay.id()))
        .map(|(position, _)| position)
        .collect();

    if candidates.is_empty() {
        return Err(NoRouteAvailable {
            message: explain_empty(pool, request),
        });
    }

    // -- 1. domain overrides ---------------------------------------------
    let recipient_domain = request.recipients.first().map(|r| address_domain(r));
    if let Some(domain) = recipient_domain {
        if let Some(rule) = match_override(&pool.routing.domain_overrides, domain) {
            let restricted: Vec<usize> = rule
                .relay_ids
                .iter()
                .filter_map(|id| pool.position_of(id))
                .filter(|position| candidates.contains(position))
                .collect();

            if !restricted.is_empty() {
                // The rule lists relays in preference order, so honour that
                // order rather than re-shuffling with the global strategy.
                return Ok(route(pool, restricted[0], "domain_override"));
            }
            if !pool.routing.fallback_on_failure {
                return Err(NoRouteAvailable {
                    message: format!(
                        "no eligible relay for domain override `{}` and routing.fallback_on_failure is disabled",
                        rule.domain
                    ),
                });
            }
        }
    }

    // -- 2. stickiness ----------------------------------------------------
    if candidates.len() > 1 {
        if let Some(key) = sticky_key(pool.routing.sticky, request, recipient_domain) {
            let position = weighted_pick_by_hash(pool, &candidates, stable_hash(&key));
            return Ok(route(pool, position, "sticky"));
        }
    }

    // -- 3. strategy -------------------------------------------------------
    let position = match pool.routing.strategy {
        Strategy::RoundRobin => candidates[pool.next_cursor(candidates.len())],
        Strategy::Weighted => pool
            .smooth_weighted_pick(&candidates)
            .unwrap_or(candidates[0]),
        Strategy::LeastUsed => {
            candidates.sort_by_key(|&position| {
                let relay = &pool.relays()[position];
                (relay.hour_count(), relay.in_flight(), position)
            });
            candidates[0]
        }
        Strategy::Failover => {
            candidates.sort_by_key(|&position| {
                let relay = &pool.relays()[position];
                (relay.config.priority, position)
            });
            candidates[0]
        }
    };

    Ok(route(pool, position, pool.routing.strategy.as_str()))
}

fn route(pool: &Pool, position: usize, reason: &'static str) -> Route {
    Route {
        relay: Arc::clone(&pool.relays()[position]),
        reason,
    }
}

/// Builds an operator-facing explanation of why the pool has nothing to offer.
fn explain_empty(pool: &Pool, request: &RouteRequest<'_>) -> String {
    let total = pool.len();
    let excluded = pool
        .relays()
        .iter()
        .filter(|relay| request.exclude.iter().any(|id| id == relay.id()))
        .count();

    let mut deactivated = 0;
    let mut circuit_open = 0;
    let mut quota = 0;
    let mut saturated = 0;
    for relay in pool.relays() {
        match relay.ineligible_reason() {
            Some("deactivated") => deactivated += 1,
            Some("circuit_open") => circuit_open += 1,
            Some("quota_reached") => quota += 1,
            Some("at_concurrency_limit") => saturated += 1,
            _ => {}
        }
    }

    let mut parts = Vec::new();
    if deactivated > 0 {
        parts.push(format!("{deactivated} deactivated"));
    }
    if circuit_open > 0 {
        parts.push(format!("{circuit_open} with an open circuit breaker"));
    }
    if quota > 0 {
        parts.push(format!("{quota} over quota"));
    }
    if saturated > 0 {
        parts.push(format!("{saturated} at their concurrency limit"));
    }
    if excluded > 0 {
        parts.push(format!("{excluded} already tried for this message"));
    }

    if parts.is_empty() {
        format!("none of the {total} configured relays is eligible")
    } else {
        format!(
            "none of the {total} configured relays is eligible: {}",
            parts.join(", ")
        )
    }
}

/// Matches `domain` against override rules; `*.example.com` matches subdomains.
fn match_override<'a>(
    rules: &'a [DomainOverride],
    domain: &str,
) -> Option<&'a DomainOverride> {
    let needle = domain.trim().trim_end_matches('.').to_ascii_lowercase();

    // Prefer an exact match over a wildcard.
    if let Some(rule) = rules
        .iter()
        .find(|rule| rule.domain.trim().to_ascii_lowercase() == needle)
    {
        return Some(rule);
    }

    rules.iter().find(|rule| {
        let pattern = rule.domain.trim().to_ascii_lowercase();
        match pattern.strip_prefix("*.") {
            Some(suffix) => needle == suffix || needle.ends_with(&format!(".{suffix}")),
            None => false,
        }
    })
}

fn sticky_key(
    mode: StickyMode,
    request: &RouteRequest<'_>,
    recipient_domain: Option<&str>,
) -> Option<String> {
    match mode {
        StickyMode::None => None,
        StickyMode::Sender => {
            let sender = request.sender.trim().to_ascii_lowercase();
            if sender.is_empty() {
                None
            } else {
                Some(sender)
            }
        }
        StickyMode::RecipientDomain => recipient_domain
            .map(|domain| domain.trim().to_ascii_lowercase())
            .filter(|domain| !domain.is_empty()),
    }
}

/// Deterministic hash used for sticky routing.
fn stable_hash(key: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

/// Maps a hash onto the candidate list proportionally to relay weight, so
/// stickiness still respects the configured traffic split.
fn weighted_pick_by_hash(pool: &Pool, candidates: &[usize], hash: u64) -> usize {
    let total: u64 = candidates
        .iter()
        .map(|&position| pool.relays()[position].config.weight.max(1) as u64)
        .sum();
    if total == 0 {
        return candidates[0];
    }

    let mut target = hash % total;
    for &position in candidates {
        let weight = pool.relays()[position].config.weight.max(1) as u64;
        if target < weight {
            return position;
        }
        target -= weight;
    }
    candidates[candidates.len() - 1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RelayConfig, RoutingConfig};
    use std::collections::HashMap;

    fn relay(id: &str, weight: u32, priority: u32) -> RelayConfig {
        RelayConfig {
            id: id.to_string(),
            host: format!("smtp.{id}.test"),
            from_address: format!("noreply@{id}.test"),
            weight,
            priority,
            max_concurrent: 1_000,
            ..Default::default()
        }
    }

    fn pool_with(relays: Vec<RelayConfig>, routing: RoutingConfig) -> Pool {
        let config = Config {
            relays,
            routing,
            ..Default::default()
        };
        Pool::build(&config).expect("pool builds")
    }

    fn request<'a>(recipients: &'a [String], exclude: &'a [String]) -> RouteRequest<'a> {
        RouteRequest {
            sender: "campaigns@acme.io",
            recipients,
            exclude,
        }
    }

    fn distribute(pool: &Pool, iterations: usize) -> HashMap<String, usize> {
        let recipients = vec!["lead@example.org".to_string()];
        let exclude: Vec<String> = Vec::new();
        let mut counts: HashMap<String, usize> = HashMap::new();
        for _ in 0..iterations {
            let route = select(pool, &request(&recipients, &exclude)).expect("route");
            *counts.entry(route.relay.id().to_string()).or_default() += 1;
        }
        counts
    }

    #[test]
    fn round_robin_is_even_and_ordered() {
        let pool = pool_with(
            vec![relay("a", 1, 100), relay("b", 1, 100), relay("c", 1, 100)],
            RoutingConfig {
                strategy: Strategy::RoundRobin,
                ..Default::default()
            },
        );

        let recipients = vec!["lead@example.org".to_string()];
        let exclude: Vec<String> = Vec::new();
        let sequence: Vec<String> = (0..6)
            .map(|_| {
                select(&pool, &request(&recipients, &exclude))
                    .unwrap()
                    .relay
                    .id()
                    .to_string()
            })
            .collect();
        assert_eq!(sequence, vec!["a", "b", "c", "a", "b", "c"]);
    }

    #[test]
    fn weighted_strategy_matches_configured_percentages() {
        let pool = pool_with(
            vec![relay("forty", 40, 100), relay("sixty", 60, 100)],
            RoutingConfig {
                strategy: Strategy::Weighted,
                ..Default::default()
            },
        );

        let counts = distribute(&pool, 1_000);
        assert_eq!(counts["forty"], 400, "40% share");
        assert_eq!(counts["sixty"], 600, "60% share");
    }

    #[test]
    fn weighted_strategy_interleaves_rather_than_clustering() {
        let pool = pool_with(
            vec![relay("forty", 40, 100), relay("sixty", 60, 100)],
            RoutingConfig {
                strategy: Strategy::Weighted,
                ..Default::default()
            },
        );

        let recipients = vec!["lead@example.org".to_string()];
        let exclude: Vec<String> = Vec::new();
        let sequence: Vec<String> = (0..10)
            .map(|_| {
                select(&pool, &request(&recipients, &exclude))
                    .unwrap()
                    .relay
                    .id()
                    .to_string()
            })
            .collect();

        // Smooth weighted round-robin never sends more than two in a row to
        // the same relay at a 40/60 split.
        let mut longest_run = 1;
        let mut run = 1;
        for pair in sequence.windows(2) {
            if pair[0] == pair[1] {
                run += 1;
                longest_run = longest_run.max(run);
            } else {
                run = 1;
            }
        }
        assert!(longest_run <= 2, "clustered: {sequence:?}");
    }

    #[test]
    fn weights_reflow_when_a_relay_is_deactivated() {
        let pool = pool_with(
            vec![
                relay("a", 25, 100),
                relay("b", 25, 100),
                relay("c", 50, 100),
            ],
            RoutingConfig {
                strategy: Strategy::Weighted,
                ..Default::default()
            },
        );

        pool.get("c").unwrap().deactivate();
        let counts = distribute(&pool, 100);
        assert_eq!(counts.get("c"), None, "deactivated relay gets no traffic");
        assert_eq!(counts["a"], 50);
        assert_eq!(counts["b"], 50);
    }

    #[test]
    fn failover_prefers_lowest_priority_then_moves_down() {
        let pool = pool_with(
            vec![
                relay("primary", 1, 10),
                relay("secondary", 1, 20),
                relay("tertiary", 1, 30),
            ],
            RoutingConfig {
                strategy: Strategy::Failover,
                ..Default::default()
            },
        );

        let counts = distribute(&pool, 20);
        assert_eq!(counts["primary"], 20);

        pool.get("primary").unwrap().deactivate();
        let counts = distribute(&pool, 5);
        assert_eq!(counts["secondary"], 5);
    }

    #[test]
    fn least_used_balances_toward_the_quietest_relay() {
        let pool = pool_with(
            vec![relay("a", 1, 100), relay("b", 1, 100)],
            RoutingConfig {
                strategy: Strategy::LeastUsed,
                ..Default::default()
            },
        );

        // Pre-load relay "a" with reservations.
        let a = pool.get("a").unwrap();
        for _ in 0..5 {
            assert!(a.try_reserve_quota());
        }

        let counts = distribute(&pool, 5);
        assert_eq!(counts["b"], 5, "quiet relay absorbs the traffic");
    }

    #[test]
    fn excluded_relays_are_skipped_on_retry() {
        let pool = pool_with(
            vec![relay("a", 1, 100), relay("b", 1, 100)],
            RoutingConfig::default(),
        );

        let recipients = vec!["lead@example.org".to_string()];
        let exclude = vec!["a".to_string()];
        for _ in 0..5 {
            let route = select(&pool, &request(&recipients, &exclude)).unwrap();
            assert_eq!(route.relay.id(), "b");
        }
    }

    #[test]
    fn domain_overrides_win_and_respect_listed_order() {
        let mut routing = RoutingConfig::default();
        routing.domain_overrides.push(DomainOverride {
            domain: "gmail.com".to_string(),
            relay_ids: vec!["b".to_string(), "a".to_string()],
        });
        let pool = pool_with(vec![relay("a", 1, 100), relay("b", 1, 100)], routing);

        let exclude: Vec<String> = Vec::new();
        let gmail = vec!["lead@gmail.com".to_string()];
        for _ in 0..5 {
            let route = select(&pool, &request(&gmail, &exclude)).unwrap();
            assert_eq!(route.relay.id(), "b");
            assert_eq!(route.reason, "domain_override");
        }

        // A domain with no rule falls back to the normal strategy.
        let other = vec!["lead@example.org".to_string()];
        let route = select(&pool, &request(&other, &exclude)).unwrap();
        assert_eq!(route.reason, "round_robin");
    }

    #[test]
    fn wildcard_overrides_match_subdomains() {
        let mut routing = RoutingConfig::default();
        routing.domain_overrides.push(DomainOverride {
            domain: "*.example.com".to_string(),
            relay_ids: vec!["b".to_string()],
        });
        let pool = pool_with(vec![relay("a", 1, 100), relay("b", 1, 100)], routing);
        let exclude: Vec<String> = Vec::new();

        for address in ["x@mail.example.com", "x@example.com", "x@a.b.example.com"] {
            let recipients = vec![address.to_string()];
            let route = select(&pool, &request(&recipients, &exclude)).unwrap();
            assert_eq!(route.relay.id(), "b", "for {address}");
        }

        let recipients = vec!["x@notexample.com".to_string()];
        let route = select(&pool, &request(&recipients, &exclude)).unwrap();
        assert_eq!(route.reason, "round_robin");
    }

    #[test]
    fn override_falls_back_when_target_is_down() {
        let mut routing = RoutingConfig::default();
        routing.fallback_on_failure = true;
        routing.domain_overrides.push(DomainOverride {
            domain: "gmail.com".to_string(),
            relay_ids: vec!["b".to_string()],
        });
        let pool = pool_with(vec![relay("a", 1, 100), relay("b", 1, 100)], routing);
        pool.get("b").unwrap().deactivate();

        let recipients = vec!["lead@gmail.com".to_string()];
        let exclude: Vec<String> = Vec::new();
        let route = select(&pool, &request(&recipients, &exclude)).unwrap();
        assert_eq!(route.relay.id(), "a");
    }

    #[test]
    fn override_can_be_made_strict() {
        let mut routing = RoutingConfig::default();
        routing.fallback_on_failure = false;
        routing.domain_overrides.push(DomainOverride {
            domain: "gmail.com".to_string(),
            relay_ids: vec!["b".to_string()],
        });
        let pool = pool_with(vec![relay("a", 1, 100), relay("b", 1, 100)], routing);
        pool.get("b").unwrap().deactivate();

        let recipients = vec!["lead@gmail.com".to_string()];
        let exclude: Vec<String> = Vec::new();
        let error = select(&pool, &request(&recipients, &exclude)).unwrap_err();
        assert!(error.message.contains("domain override"), "{error}");
    }

    #[test]
    fn sender_stickiness_is_stable_and_spread() {
        let pool = pool_with(
            vec![relay("a", 1, 100), relay("b", 1, 100), relay("c", 1, 100)],
            RoutingConfig {
                sticky: StickyMode::Sender,
                ..Default::default()
            },
        );

        let recipients = vec!["lead@example.org".to_string()];
        let exclude: Vec<String> = Vec::new();

        let first = select(&pool, &request(&recipients, &exclude)).unwrap();
        for _ in 0..20 {
            let next = select(&pool, &request(&recipients, &exclude)).unwrap();
            assert_eq!(next.relay.id(), first.relay.id(), "sticky must not drift");
            assert_eq!(next.reason, "sticky");
        }

        // Different senders should not all land on one relay.
        let mut landed = std::collections::HashSet::new();
        for index in 0..40 {
            let sender = format!("sender{index}@acme.io");
            let route = select(
                &pool,
                &RouteRequest {
                    sender: &sender,
                    recipients: &recipients,
                    exclude: &exclude,
                },
            )
            .unwrap();
            landed.insert(route.relay.id().to_string());
        }
        assert!(landed.len() > 1, "stickiness collapsed onto one relay");
    }

    #[test]
    fn recipient_domain_stickiness_groups_by_domain() {
        let pool = pool_with(
            vec![relay("a", 1, 100), relay("b", 1, 100)],
            RoutingConfig {
                sticky: StickyMode::RecipientDomain,
                ..Default::default()
            },
        );
        let exclude: Vec<String> = Vec::new();

        let gmail = vec!["one@gmail.com".to_string()];
        let gmail_two = vec!["two@gmail.com".to_string()];
        let first = select(&pool, &request(&gmail, &exclude)).unwrap();
        let second = select(&pool, &request(&gmail_two, &exclude)).unwrap();
        assert_eq!(first.relay.id(), second.relay.id());
    }

    #[test]
    fn quota_exhaustion_removes_a_relay_from_rotation() {
        let mut relay_a = relay("a", 1, 100);
        relay_a.max_per_hour = Some(2);
        let pool = pool_with(vec![relay_a, relay("b", 1, 100)], RoutingConfig::default());

        let a = pool.get("a").unwrap();
        assert!(a.try_reserve_quota());
        assert!(a.try_reserve_quota());
        assert!(!a.try_reserve_quota(), "third reservation exceeds the cap");
        assert!(!a.is_eligible());
        assert_eq!(a.ineligible_reason(), Some("quota_reached"));

        let counts = distribute(&pool, 10);
        assert_eq!(counts["b"], 10);

        // Releasing a reservation puts it back in rotation.
        a.release_quota();
        assert!(a.is_eligible());
    }

    #[test]
    fn per_minute_quota_exhaustion_removes_a_relay_from_rotation() {
        let mut relay_a = relay("a", 1, 100);
        relay_a.max_per_minute = Some(1);
        let pool = pool_with(vec![relay_a, relay("b", 1, 100)], RoutingConfig::default());

        let a = pool.get("a").unwrap();
        assert!(a.try_reserve_quota());
        assert!(!a.try_reserve_quota());
        assert_eq!(a.ineligible_reason(), Some("quota_reached"));
    }

    #[test]
    fn concurrency_limit_removes_a_relay_from_rotation() {
        let mut relay_a = relay("a", 1, 100);
        relay_a.max_concurrent = 1;
        let pool = pool_with(vec![relay_a], RoutingConfig::default());

        let a = pool.get("a").unwrap();
        let guard = a.begin_delivery();
        assert!(!a.is_eligible());
        assert_eq!(a.ineligible_reason(), Some("at_concurrency_limit"));

        drop(guard);
        assert!(a.is_eligible(), "guard must release the slot");
    }

    #[test]
    fn deactivate_all_then_activate_all_round_trips() {
        let pool = pool_with(
            vec![relay("a", 1, 100), relay("b", 1, 100), relay("c", 1, 100)],
            RoutingConfig::default(),
        );

        let changed = pool.deactivate_all();
        assert_eq!(changed.len(), 3);
        assert_eq!(pool.active_count(), 0);

        let recipients = vec!["lead@example.org".to_string()];
        let exclude: Vec<String> = Vec::new();
        let error = select(&pool, &request(&recipients, &exclude)).unwrap_err();
        assert!(error.message.contains("3 deactivated"), "{error}");

        let changed = pool.activate_all();
        assert_eq!(changed.len(), 3);
        assert_eq!(pool.active_count(), 3);
        assert!(select(&pool, &request(&recipients, &exclude)).is_ok());
    }

    #[test]
    fn set_exclusive_activates_only_the_listed_relays() {
        let pool = pool_with(
            vec![relay("a", 1, 100), relay("b", 1, 100), relay("c", 1, 100)],
            RoutingConfig::default(),
        );

        let (_, unknown) = pool.set_exclusive(&["b".to_string()]);
        assert!(unknown.is_empty());
        assert!(!pool.get("a").unwrap().is_active());
        assert!(pool.get("b").unwrap().is_active());
        assert!(!pool.get("c").unwrap().is_active());

        let (_, unknown) = pool.set_exclusive(&["nope".to_string()]);
        assert_eq!(unknown, vec!["nope".to_string()]);
    }

    #[test]
    fn weight_percentages_track_the_active_set() {
        let pool = pool_with(
            vec![relay("forty", 40, 100), relay("sixty", 60, 100)],
            RoutingConfig {
                strategy: Strategy::Weighted,
                ..Default::default()
            },
        );

        let percentages = pool.weight_percentages();
        assert!((percentages["forty"] - 40.0).abs() < 0.001);
        assert!((percentages["sixty"] - 60.0).abs() < 0.001);

        pool.get("sixty").unwrap().deactivate();
        let percentages = pool.weight_percentages();
        assert!((percentages["forty"] - 100.0).abs() < 0.001);
        assert_eq!(percentages["sixty"], 0.0);
    }
}
