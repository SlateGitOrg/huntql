//! Source spans and span-accurate diagnostics.
//!
//! Every token, AST node and planner error carries a [`Span`] (a half-open
//! byte range into the query text). [`Diagnostic::render`] turns a span back
//! into a `rustc`-style snippet with a caret underline, so users see exactly
//! which part of a pipeline is wrong.

use std::fmt;

/// A half-open byte range `[start, end)` into the query source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        debug_assert!(start <= end, "span start must not exceed end");
        Span { start, end }
    }

    /// The smallest span covering both `self` and `other`.
    pub fn to(self, other: Span) -> Span {
        Span::new(self.start.min(other.start), self.end.max(other.end))
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Which phase of query processing produced a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Lex,
    Parse,
    Plan,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Phase::Lex => "lex",
            Phase::Parse => "parse",
            Phase::Plan => "plan",
        })
    }
}

/// An error tied to a location in the query text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub phase: Phase,
    pub message: String,
    pub span: Span,
    /// Short text printed next to the caret underline.
    pub label: Option<String>,
    /// Optional suggestion printed after the snippet.
    pub help: Option<String>,
}

impl Diagnostic {
    pub fn new(phase: Phase, message: impl Into<String>, span: Span) -> Self {
        Diagnostic {
            phase,
            message: message.into(),
            span,
            label: None,
            help: None,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Render the diagnostic against the source it was produced from.
    ///
    /// ```text
    /// error[plan]: unknown field `dprt` in `conn`
    ///  --> 1:15
    ///   |
    /// 1 | conn | where dprt == 443
    ///   |              ^^^^ did you mean `dport`?
    /// ```
    pub fn render(&self, source: &str) -> String {
        let (line_no, col, line) = locate(source, self.span.start);
        let line_text = line.trim_end_matches(['\r', '\n']);
        // Clamp the underline to the current line; multi-line spans underline
        // to the end of the first line.
        let line_end_offset = line_text.len();
        let start_col = col;
        let end_col = (col + self.span.len()).min(line_end_offset.max(col + 1));
        let carets = "^".repeat(end_col.saturating_sub(start_col).max(1));
        let gutter = line_no.to_string().len();
        let pad = " ".repeat(gutter);
        let lead: String = line_text
            .chars()
            .take(char_count(line_text, start_col))
            .map(|c| if c == '\t' { '\t' } else { ' ' })
            .collect();
        let mut out = format!(
            "error[{}]: {}\n{pad}--> {}:{}\n{pad} |\n{} | {}\n{pad} | {}{}",
            self.phase,
            self.message,
            line_no,
            char_count(line_text, start_col) + 1,
            line_no,
            line_text,
            lead,
            carets
        );
        if let Some(label) = &self.label {
            out.push(' ');
            out.push_str(label);
        }
        if let Some(help) = &self.help {
            out.push_str(&format!("\n{pad} = help: {help}"));
        }
        out
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} error at {}..{}: {}",
            self.phase, self.span.start, self.span.end, self.message
        )
    }
}

impl std::error::Error for Diagnostic {}

/// Number of chars in the first `byte_len` bytes of `s`.
fn char_count(s: &str, byte_len: usize) -> usize {
    let mut end = byte_len.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].chars().count()
}

/// Returns (1-based line number, byte column within line, line text).
fn locate(source: &str, offset: usize) -> (usize, usize, &str) {
    let offset = offset.min(source.len());
    let mut line_start = 0;
    let mut line_no = 1;
    for (i, b) in source.bytes().enumerate() {
        if i >= offset {
            break;
        }
        if b == b'\n' {
            line_no += 1;
            line_start = i + 1;
        }
    }
    let line_end = source[line_start..]
        .find('\n')
        .map(|p| line_start + p)
        .unwrap_or(source.len());
    (line_no, offset - line_start, &source[line_start..line_end])
}

/// Levenshtein edit distance, used for "did you mean" suggestions.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// The closest candidate to `name` within a small edit distance, if any.
pub fn suggest<'a>(name: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let limit = (name.len() / 3).max(1) + 1;
    candidates
        .into_iter()
        .map(|c| (edit_distance(name, c), c))
        .filter(|(d, _)| *d <= limit)
        .min_by_key(|(d, c)| (*d, c.len()))
        .map(|(_, c)| c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_caret_under_span() {
        let src = "conn | where dprt == 443";
        let d = Diagnostic::new(Phase::Plan, "unknown field `dprt`", Span::new(13, 17))
            .with_label("did you mean `dport`?");
        let r = d.render(src);
        assert!(r.contains("1 | conn | where dprt == 443"), "{r}");
        assert!(
            r.contains("  |              ^^^^ did you mean `dport`?"),
            "{r}"
        );
        assert!(r.contains("--> 1:14"), "{r}");
    }

    #[test]
    fn renders_second_line_and_help() {
        let src = "conn\n| head x";
        let d = Diagnostic::new(Phase::Parse, "expected integer", Span::new(12, 13))
            .with_help("head takes a row count");
        let r = d.render(src);
        assert!(r.contains("2 | | head x"), "{r}");
        assert!(r.contains("--> 2:8"), "{r}");
        assert!(r.contains("= help: head takes a row count"), "{r}");
    }

    #[test]
    fn empty_span_at_end_gets_one_caret() {
        let src = "conn |";
        let d = Diagnostic::new(Phase::Parse, "expected operator", Span::new(6, 6));
        assert!(d.render(src).contains("|       ^"));
    }

    #[test]
    fn suggestions() {
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(suggest("dprt", ["dport", "sport", "src"]), Some("dport"));
        assert_eq!(suggest("zzzzzz", ["dport", "src"]), None);
    }

    #[test]
    fn span_merge() {
        assert_eq!(Span::new(3, 5).to(Span::new(1, 4)), Span::new(1, 5));
        assert!(Span::new(2, 2).is_empty());
    }
}
