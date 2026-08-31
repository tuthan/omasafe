//! Recursion and work budget for analyzing untrusted shell text.

/// Recursion and work budget for analyzing untrusted shell text: bounds how
/// deep compound-group and substitution recursion may descend and how many
/// tokens (or characters, for re-tokenised substitution text) the whole
/// analysis may visit, so adversarial nesting degrades to a disclosed
/// coverage limitation instead of unbounded recursion.
pub(in crate::detect) const MAX_SHELL_ANALYSIS_DEPTH: u32 = 64;
pub(in crate::detect) const MAX_SHELL_ANALYSIS_NODES: u32 = 250_000;
const MAX_BODY_SUMMARY_ENTRIES: usize = 64;
const MAX_BODY_SUMMARY_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
pub(in crate::detect) struct CachedStdinSummary {
    pub(in crate::detect) consumes_stdin_as_code: bool,
    pub(in crate::detect) drains_stdin: bool,
    pub(in crate::detect) forwards_stdin_body: bool,
}

#[derive(Clone, Copy)]
pub(in crate::detect) struct CachedFindingSummary {
    pub(in crate::detect) download_execute: bool,
    pub(in crate::detect) decode_execute: bool,
    pub(in crate::detect) reverse_shell: bool,
    pub(in crate::detect) shared_temp_indicator: bool,
    pub(in crate::detect) shared_temp_controlled: bool,
}

struct BodySummaryCacheEntry {
    body: String,
    stdin: Option<CachedStdinSummary>,
    fetch_egress: Option<bool>,
    live_fetch_stdout: Option<bool>,
    findings: Option<CachedFindingSummary>,
}

pub(in crate::detect) struct ShellBudget {
    pub(in crate::detect) depth: u32,
    pub(in crate::detect) nodes: u32,
    pub(in crate::detect) exhausted: bool,
    body_summaries: Vec<BodySummaryCacheEntry>,
    body_summary_bytes: usize,
}

impl ShellBudget {
    pub(in crate::detect) fn new() -> Self {
        Self {
            depth: MAX_SHELL_ANALYSIS_DEPTH,
            nodes: MAX_SHELL_ANALYSIS_NODES,
            exhausted: false,
            body_summaries: Vec::new(),
            body_summary_bytes: 0,
        }
    }

    pub(in crate::detect) fn cached_stdin_summary(&self, body: &str) -> Option<CachedStdinSummary> {
        self.body_summaries
            .iter()
            .find_map(|entry| (entry.body == body).then_some(entry.stdin).flatten())
    }

    pub(in crate::detect) fn cache_stdin_summary(
        &mut self,
        body: &str,
        summary: CachedStdinSummary,
    ) {
        if let Some(entry) = self
            .body_summaries
            .iter_mut()
            .find(|entry| entry.body == body)
        {
            entry.stdin = Some(summary);
            return;
        }
        if !self.can_cache_body(body) {
            return;
        }
        self.insert_body_summary(body, Some(summary), None, None, None);
    }

    pub(in crate::detect) fn cached_fetch_egress(&self, body: &str) -> Option<bool> {
        self.body_summaries
            .iter()
            .find_map(|entry| (entry.body == body).then_some(entry.fetch_egress).flatten())
    }

    pub(in crate::detect) fn cache_fetch_egress(&mut self, body: &str, fetches: bool) {
        if let Some(entry) = self
            .body_summaries
            .iter_mut()
            .find(|entry| entry.body == body)
        {
            entry.fetch_egress = Some(fetches);
            return;
        }
        if !self.can_cache_body(body) {
            return;
        }
        self.insert_body_summary(body, None, Some(fetches), None, None);
    }

    pub(in crate::detect) fn cached_live_fetch_stdout(&self, body: &str) -> Option<bool> {
        self.body_summaries.iter().find_map(|entry| {
            (entry.body == body)
                .then_some(entry.live_fetch_stdout)
                .flatten()
        })
    }

    pub(in crate::detect) fn cache_live_fetch_stdout(&mut self, body: &str, reaches_stdout: bool) {
        if let Some(entry) = self
            .body_summaries
            .iter_mut()
            .find(|entry| entry.body == body)
        {
            entry.live_fetch_stdout = Some(reaches_stdout);
            return;
        }
        if !self.can_cache_body(body) {
            return;
        }
        self.insert_body_summary(body, None, None, Some(reaches_stdout), None);
    }

    pub(in crate::detect) fn cached_finding_summary(
        &self,
        body: &str,
    ) -> Option<CachedFindingSummary> {
        self.body_summaries
            .iter()
            .find_map(|entry| (entry.body == body).then_some(entry.findings).flatten())
    }

    pub(in crate::detect) fn cache_finding_summary(
        &mut self,
        body: &str,
        summary: CachedFindingSummary,
    ) {
        if let Some(entry) = self
            .body_summaries
            .iter_mut()
            .find(|entry| entry.body == body)
        {
            entry.findings = Some(summary);
            return;
        }
        if !self.can_cache_body(body) {
            return;
        }
        self.insert_body_summary(body, None, None, None, Some(summary));
    }

    /// Keep the cache bounded by both entry count and source bytes. Bodies
    /// larger than the byte ceiling are cheaper to reparse than to retain,
    /// and a full cache simply skips future insertion without evicting a
    /// summary that this analysis may still reuse.
    fn can_cache_body(&self, body: &str) -> bool {
        if body.is_empty()
            || body.len() > MAX_BODY_SUMMARY_BYTES
            || self.body_summaries.len() >= MAX_BODY_SUMMARY_ENTRIES
            || self.body_summary_bytes + body.len() > MAX_BODY_SUMMARY_BYTES
        {
            return false;
        }
        true
    }

    fn insert_body_summary(
        &mut self,
        body: &str,
        stdin: Option<CachedStdinSummary>,
        fetch_egress: Option<bool>,
        live_fetch_stdout: Option<bool>,
        findings: Option<CachedFindingSummary>,
    ) {
        self.body_summary_bytes += body.len();
        self.body_summaries.push(BodySummaryCacheEntry {
            body: body.to_owned(),
            stdin,
            fetch_egress,
            live_fetch_stdout,
            findings,
        });
    }

    /// Charge one analysis step for the tokens it walks; past the budget the
    /// step is refused and the budget stays exhausted for the rest of the
    /// pass, so callers report the shortfall instead of recursing without
    /// bound.
    pub(in crate::detect) fn spend(&mut self, tokens: usize) -> bool {
        if self.exhausted {
            return false;
        }
        let charge = tokens.min(u32::MAX as usize) as u32;
        if charge > self.nodes {
            self.nodes = 0;
            self.exhausted = true;
            return false;
        }
        self.nodes -= charge;
        true
    }

    /// Descend one recursion level; `false` refuses the descent (and marks
    /// the budget exhausted) at the depth ceiling.
    pub(in crate::detect) fn enter(&mut self) -> bool {
        if self.exhausted || self.depth == 0 {
            self.exhausted = true;
            return false;
        }
        self.depth -= 1;
        true
    }

    pub(in crate::detect) fn leave(&mut self) {
        self.depth = self.depth.saturating_add(1).min(MAX_SHELL_ANALYSIS_DEPTH);
    }

    pub(in crate::detect) fn exhausted(&self) -> bool {
        self.exhausted
    }
}
