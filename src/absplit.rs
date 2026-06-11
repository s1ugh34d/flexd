use crate::config::{AbGroup, AbSplit};
use std::collections::HashMap;
use std::sync::Mutex;

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
