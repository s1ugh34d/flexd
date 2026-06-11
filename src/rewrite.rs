use crate::config::RewriteRule;
use regex::Regex;

pub struct RewriteEngine {
    rules: Vec<(Regex, String, String)>,
}

impl RewriteEngine {
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

    pub fn rewrite(&self, path: &str) -> Option<(String, bool)> {
        for (re, replacement, flag) in &self.rules {
            if re.is_match(path) {
                let result = re.replace(path, replacement.as_str());
                let should_break = flag == "break" || flag == "last";
                return Some((result.into_owned(), should_break));
            }
        }
        None
    }
}
