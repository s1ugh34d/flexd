//! Regex-based path rewriting and redirects.
//!
//! [`RewriteEngine`](crate::rewrite::RewriteEngine) compiles a block's
//! `[[http.rewrites]]` rules once and
//! applies the first match to each request path. A rule's `flag` decides the
//! outcome: `break`/`last` rewrite the path internally and routing continues,
//! while `redirect`/`permanent` emit a 302/301 response. Patterns that fail to
//! compile are silently dropped (the config validator rejects them up front, so
//! this only guards against a slip-through).

use crate::config::RewriteRule;
use regex::Regex;

/// Outcome of a matched rewrite rule.
#[derive(Debug)]
pub enum RewriteAction {
    /// Rewrite the path internally and continue routing.
    Internal(String),
    /// Send an HTTP redirect to the rewritten target.
    Redirect {
        /// The rewritten URL to redirect to.
        target: String,
        /// The redirect status code (301 for `permanent`, 302 for `redirect`).
        status: u16,
    },
}

/// A compiled set of rewrite rules, evaluated in order.
pub struct RewriteEngine {
    rules: Vec<(Regex, String, String)>,
}

impl RewriteEngine {
    /// Compile the given rules. Rules whose pattern fails to compile are
    /// skipped (config validation rejects bad patterns before this point).
    pub fn new(rules: &[RewriteRule]) -> Self {
        let compiled: Vec<_> = rules
            .iter()
            .filter_map(|rule| {
                Regex::new(&rule.pattern)
                    .ok()
                    .map(|re| (re, rule.replacement.clone(), rule.flag.clone()))
            })
            .collect();

        Self { rules: compiled }
    }

    /// Whether any rules compiled successfully (lets the caller skip the
    /// rewrite stage entirely when there is nothing to do).
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Apply the first matching rule. `redirect`/`permanent` flags become
    /// 302/301 responses; `break`/`last` rewrite the path internally.
    pub fn apply(&self, path: &str) -> Option<RewriteAction> {
        for (re, replacement, flag) in &self.rules {
            if re.is_match(path) {
                let result = re.replace(path, replacement.as_str()).into_owned();
                return Some(match flag.as_str() {
                    "redirect" => RewriteAction::Redirect { target: result, status: 302 },
                    "permanent" => RewriteAction::Redirect { target: result, status: 301 },
                    _ => RewriteAction::Internal(result),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, replacement: &str, flag: &str) -> RewriteRule {
        RewriteRule {
            pattern: pattern.into(),
            replacement: replacement.into(),
            flag: flag.into(),
        }
    }

    #[test]
    fn internal_rewrite() {
        let e = RewriteEngine::new(&[rule("^/old/(.*)$", "/new/$1", "break")]);
        match e.apply("/old/page") {
            Some(RewriteAction::Internal(p)) => assert_eq!(p, "/new/page"),
            other => panic!("unexpected: {:?}", other.is_some()),
        }
    }

    #[test]
    fn redirect_flags_map_to_statuses() {
        let e = RewriteEngine::new(&[rule("^/moved$", "/here", "permanent")]);
        match e.apply("/moved") {
            Some(RewriteAction::Redirect { target, status }) => {
                assert_eq!(target, "/here");
                assert_eq!(status, 301);
            }
            _ => panic!("expected redirect"),
        }
    }

    #[test]
    fn no_match_passes_through() {
        let e = RewriteEngine::new(&[rule("^/old$", "/new", "break")]);
        assert!(e.apply("/other").is_none());
    }
}
