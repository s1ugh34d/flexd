//! Weighted A/B traffic splitting.
//!
//! A proxy [`Location`](crate::config::Location) can route through a named
//! [`AbSplit`](crate::config::AbSplit) instead of a fixed upstream. The router
//! assigns each request to
//! one of the split's weighted groups; with `sticky = true`, a given session
//! identifier always lands in the same group for the life of the process.
//!
//! Assignment is deterministic per `(session_id, split_name)` pair: the pair is
//! hashed and mapped onto the cumulative-weight ranges of the groups, so the
//! same session reproducibly resolves to the same group even without sticky
//! bookkeeping (sticky mode additionally pins the *first* observed assignment,
//! which matters if group weights are later reconfigured).

use crate::config::{AbGroup, AbSplit};
use std::collections::HashMap;
use std::sync::Mutex;

/// Upper bound on remembered sticky sessions; prevents unbounded memory
/// growth from an attacker cycling session identifiers.
const MAX_STICKY_SESSIONS: usize = 10_000;

/// Resolves session identifiers to A/B groups across all configured splits.
///
/// Built once per [`HttpBlock`](crate::config::HttpBlock) and shared across
/// requests; the sticky-session table is internally synchronized.
pub struct AbSplitRouter {
    splits: HashMap<String, AbSplitConfig>,
    sticky_sessions: Mutex<HashMap<String, String>>,
}

struct AbSplitConfig {
    groups: Vec<AbGroup>,
    total_weight: u32,
    sticky: bool,
}

impl AbSplitRouter {
    /// Build a router from a block's split definitions, precomputing each
    /// split's total weight.
    pub fn new(splits: &[AbSplit]) -> Self {
        let mut split_map = HashMap::new();

        for split in splits {
            let total_weight: u32 = split.groups.iter().map(|g| g.weight).sum();
            split_map.insert(
                split.name.clone(),
                AbSplitConfig {
                    groups: split.groups.clone(),
                    total_weight,
                    sticky: split.sticky,
                },
            );
        }

        Self {
            splits: split_map,
            sticky_sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve `session_id` to a group name within the named split.
    ///
    /// Returns the chosen [`AbGroup::name`](crate::config::AbGroup::name).
    /// Returns `None` if `split_name` is
    /// unknown or the split has no positive total weight. In sticky mode a
    /// previously seen session returns its pinned group; otherwise assignment
    /// is by deterministic hash over `(session_id, split_name)`.
    pub fn resolve(&self, split_name: &str, session_id: &str) -> Option<String> {
        let config = self.splits.get(split_name)?;

        if config.sticky {
            if let Ok(sessions) = self.sticky_sessions.lock() {
                if let Some(group_name) = sessions.get(session_id) {
                    return Some(group_name.clone());
                }
            }
        }

        if config.total_weight == 0 {
            return None;
        }

        let hash = AbSplitRouter::hash_session(session_id, split_name) as u32 % config.total_weight;
        let mut cumulative = 0u32;

        for group in &config.groups {
            cumulative += group.weight;
            if hash < cumulative {
                if config.sticky {
                    if let Ok(mut sessions) = self.sticky_sessions.lock() {
                        if sessions.len() >= MAX_STICKY_SESSIONS {
                            sessions.clear();
                        }
                        sessions.insert(session_id.to_string(), group.name.clone());
                    }
                }
                return Some(group.name.clone());
            }
        }

        config.groups.first().map(|g| g.name.clone())
    }

    fn hash_session(session_id: &str, split_name: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        session_id.hash(&mut hasher);
        split_name.hash(&mut hasher);
        hasher.finish()
    }
}
