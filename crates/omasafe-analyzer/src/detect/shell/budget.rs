//! Recursion and work budget for analyzing untrusted shell text.

/// Recursion and work budget for analyzing untrusted shell text: bounds how
/// deep compound-group and substitution recursion may descend and how many
/// tokens (or characters, for re-tokenised substitution text) the whole
/// analysis may visit, so adversarial nesting degrades to a disclosed
/// coverage limitation instead of unbounded recursion.
pub(in crate::detect) const MAX_SHELL_ANALYSIS_DEPTH: u32 = 64;
pub(in crate::detect) const MAX_SHELL_ANALYSIS_NODES: u32 = 250_000;

pub(in crate::detect) struct ShellBudget {
    pub(in crate::detect) depth: u32,
    pub(in crate::detect) nodes: u32,
    pub(in crate::detect) exhausted: bool,
}

impl ShellBudget {
    pub(in crate::detect) fn new() -> Self {
        Self {
            depth: MAX_SHELL_ANALYSIS_DEPTH,
            nodes: MAX_SHELL_ANALYSIS_NODES,
            exhausted: false,
        }
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
