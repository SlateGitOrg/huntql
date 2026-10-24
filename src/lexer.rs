//! Hand-written lexer for the huntql query language.
//!
//! The lexer is a single forward pass over the UTF-8 source producing tokens
//! with exact byte spans. Numeric-looking input is classified by shape:
//! `443` is an integer, `0.5` a float, `30s` / `1.5m` a duration,
//! `10.0.0.1` an IPv4 address and `10.0.0.0/8` a subnet. IPv6 addresses are
//! written as string literals and coerced by the planner.

use std::fmt;

use crate::diag::{Diagnostic, Phase, Span};
use crate::timefmt;

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    Ident(String),
    Str(String),
    Int(i64),
    Float(f64),
    /// Duration in microseconds.
    Duration(i64),
    Ip(std::net::IpAddr),
    Cidr(crate::value::Subnet),
    // Keywords
    And,
    Or,
    Not,
    In,
    By,
    As,
    True,
    False,
    Null,
    // Punctuation
    Pipe,
    Comma,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eq,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    Match,
    NotMatch,
    Semi,
    Eof,
}

impl TokenKind {
    /// Short description used in "expected X, found Y" messages.
    pub fn describe(&self) -> String {
        match self {
            TokenKind::Ident(s) => format!("identifier `{s}`"),
            TokenKind::Str(_) => "string literal".into(),
            TokenKind::Int(_) => "integer".into(),
            TokenKind::Float(_) => "float".into(),
            TokenKind::Duration(_) => "duration".into(),
            TokenKind::Ip(_) => "IP address".into(),
            TokenKind::Cidr(_) => "subnet".into(),
            TokenKind::Eof => "end of query".into(),
            other => format!("`{other}`"),
        }
    }
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TokenKind::Ident(s) => return f.write_str(s),
            TokenKind::Str(s) => return write!(f, "{s:?}"),
            TokenKind::Int(i) => return write!(f, "{i}"),
            TokenKind::Float(x) => return write!(f, "{x}"),
            TokenKind::Duration(us) => return f.write_str(&timefmt::format_duration(*us)),
            TokenKind::Ip(ip) => return write!(f, "{ip}"),
            TokenKind::Cidr(c) => return write!(f, "{c}"),
            TokenKind::And => "and",
            TokenKind::Or => "or",
            TokenKind::Not => "not",
            TokenKind::In => "in",
            TokenKind::By => "by",
            TokenKind::As => "as",
            TokenKind::True => "true",
            TokenKind::False => "false",
            TokenKind::Null => "null",
            TokenKind::Pipe => "|",
            TokenKind::Comma => ",",
            TokenKind::LParen => "(",
            TokenKind::RParen => ")",
            TokenKind::LBracket => "[",
            TokenKind::RBracket => "]",
            TokenKind::Plus => "+",
            TokenKind::Minus => "-",
            TokenKind::Star => "*",
            TokenKind::Slash => "/",
            TokenKind::Percent => "%",
            TokenKind::Eq => "=",
            TokenKind::EqEq => "==",
            TokenKind::NotEq => "!=",
            TokenKind::Lt => "<",
            TokenKind::Le => "<=",
            TokenKind::Gt => ">",
            TokenKind::Ge => ">=",
            TokenKind::Match => "=~",
            TokenKind::NotMatch => "!~",
            TokenKind::Semi => ";",
            TokenKind::Eof => "<eof>",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

/// Tokenize a whole query. Comments (`# ...` and `// ...` to end of line)
/// and whitespace are skipped. The result always ends with an `Eof` token.
pub fn lex(src: &str) -> Result<Vec<Token>, Diagnostic> {
    Lexer { src, pos: 0 }.run()
}

struct Lexer<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn run(mut self) -> Result<Vec<Token>, Diagnostic> {
        let mut out = Vec::new();
        loop {
            self.skip_trivia();
            let start = self.pos;
            let Some(c) = self.peek() else {
                out.push(Token {
                    kind: TokenKind::Eof,
                    span: Span::new(start, start),
                });
                return Ok(out);
            };
            let kind = match c {
                '|' => self.single(TokenKind::Pipe),
                ',' => self.single(TokenKind::Comma),
                '(' => self.single(TokenKind::LParen),
                ')' => self.single(TokenKind::RParen),
                '[' => self.single(TokenKind::LBracket),
                ']' => self.single(TokenKind::RBracket),
                '+' => self.single(TokenKind::Plus),
                '-' => self.single(TokenKind::Minus),
                '*' => self.single(TokenKind::Star),
                '/' => self.single(TokenKind::Slash),
                '%' => self.single(TokenKind::Percent),
                ';' => self.single(TokenKind::Semi),
                '=' => self.one_of('=', TokenKind::EqEq, '~', TokenKind::Match, TokenKind::Eq),
                '<' => self.one_of('=', TokenKind::Le, '\0', TokenKind::Le, TokenKind::Lt),
                '>' => self.one_of('=', TokenKind::Ge, '\0', TokenKind::Ge, TokenKind::Gt),
                '!' => {
                    self.bump();
                    match self.peek() {
                        Some('=') => self.single(TokenKind::NotEq),
                        Some('~') => self.single(TokenKind::NotMatch),
                        _ => {
                            return Err(Diagnostic::new(
                                Phase::Lex,
                                "unexpected character `!`",
                                Span::new(start, self.pos),
                            )
                            .with_help("use `not` for negation, `!=` or `!~` for comparisons"))
                        }
                    }
                }
                '"' | '\'' => self.string(c)?,
                c if c.is_ascii_digit() => self.number()?,
                c if c.is_alphabetic() || c == '_' => self.ident(),
                other => {
                    self.bump();
                    return Err(Diagnostic::new(
                        Phase::Lex,
                        format!("unexpected character `{other}`"),
                        Span::new(start, self.pos),
                    ));
                }
            };
            out.push(Token {
                kind,
                span: Span::new(start, self.pos),
            });
        }
    }

    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn peek_at(&self, n: usize) -> Option<char> {
        self.src[self.pos..].chars().nth(n)
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn single(&mut self, kind: TokenKind) -> TokenKind {
        self.bump();
        kind
    }

    fn one_of(
        &mut self,
        a: char,
        ka: TokenKind,
        b: char,
        kb: TokenKind,
        default: TokenKind,
    ) -> TokenKind {
        self.bump();
        match self.peek() {
            Some(c) if c == a => self.single(ka),
            Some(c) if c == b => self.single(kb),
            _ => default,
        }
    }

    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => {
                    self.bump();
                }
                Some('#') => self.skip_line(),
                Some('/') if self.peek_at(1) == Some('/') => self.skip_line(),
                _ => return,
            }
        }
    }

    fn skip_line(&mut self) {
        while let Some(c) = self.bump() {
            if c == '\n' {
                break;
            }
        }
    }

    fn string(&mut self, quote: char) -> Result<TokenKind, Diagnostic> {
        let start = self.pos;
        self.bump();
        let mut s = String::new();
        loop {
            let esc_start = self.pos;
            match self.bump() {
                None => {
                    return Err(Diagnostic::new(
                        Phase::Lex,
                        "unterminated string literal",
                        Span::new(start, self.pos),
                    )
                    .with_label("string starts here")
                    .with_help(format!("add a closing {quote}")))
                }
                Some(c) if c == quote => return Ok(TokenKind::Str(s)),
                Some('\\') => match self.bump() {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('\\') => s.push('\\'),
                    Some('"') => s.push('"'),
                    Some('\'') => s.push('\''),
                    // Keep unknown escapes verbatim so regexes like "\d+" work.
                    Some(other) => {
                        s.push('\\');
                        s.push(other);
                    }
                    None => {
                        return Err(Diagnostic::new(
                            Phase::Lex,
                            "unterminated escape sequence",
                            Span::new(esc_start, self.pos),
                        ))
                    }
                },
                Some(c) => s.push(c),
            }
        }
    }

    fn ident(&mut self) -> TokenKind {
        let start = self.pos;
        while let Some(c) = self.peek() {
            let dotted = c == '.'
                && self
                    .peek_at(1)
                    .is_some_and(|n| n.is_alphabetic() || n == '_');
            if c.is_alphanumeric() || c == '_' || dotted {
                self.bump();
            } else {
                break;
            }
        }
        match &self.src[start..self.pos] {
            "and" => TokenKind::And,
            "or" => TokenKind::Or,
            "not" => TokenKind::Not,
            "in" => TokenKind::In,
            "by" => TokenKind::By,
            "as" => TokenKind::As,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "null" => TokenKind::Null,
            other => TokenKind::Ident(other.to_string()),
        }
    }

    fn number(&mut self) -> Result<TokenKind, Diagnostic> {
        let start = self.pos;
        let mut dots = 0;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.bump();
            } else if c == '.' && self.peek_at(1).is_some_and(|n| n.is_ascii_digit()) {
                dots += 1;
                self.bump();
            } else {
                break;
            }
        }
        let numeric = &self.src[start..self.pos];
        let err = |msg: String, end: usize| Diagnostic::new(Phase::Lex, msg, Span::new(start, end));
        match dots {
            0 | 1 => {
                // Optional duration unit.
                if self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
                    while self.peek().is_some_and(|c| c.is_ascii_alphanumeric()) {
                        self.bump();
                    }
                    let text = &self.src[start..self.pos];
                    return timefmt::parse_duration_literal(text)
                        .map(TokenKind::Duration)
                        .ok_or_else(|| {
                            err(format!("invalid duration literal `{text}`"), self.pos).with_help(
                                "durations use the units us, ms, s, m, h, d (e.g. `30s`, `1.5h`)",
                            )
                        });
                }
                if dots == 0 {
                    numeric.parse().map(TokenKind::Int).map_err(|_| {
                        err(
                            format!("integer literal `{numeric}` is out of range"),
                            self.pos,
                        )
                    })
                } else {
                    // A float literal always parses once the shape is digits.digits.
                    Ok(TokenKind::Float(numeric.parse().unwrap_or(f64::NAN)))
                }
            }
            3 => {
                let ip: std::net::Ipv4Addr = numeric
                    .parse()
                    .map_err(|_| err(format!("invalid IPv4 address `{numeric}`"), self.pos))?;
                if self.peek() == Some('/') && self.peek_at(1).is_some_and(|c| c.is_ascii_digit()) {
                    self.bump();
                    while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                        self.bump();
                    }
                    let text = &self.src[start..self.pos];
                    return crate::value::Subnet::parse(text)
                        .map(TokenKind::Cidr)
                        .ok_or_else(|| err(format!("invalid subnet `{text}`"), self.pos));
                }
                Ok(TokenKind::Ip(std::net::IpAddr::V4(ip)))
            }
            _ => Err(err(format!("malformed number `{numeric}`"), self.pos)
                .with_help("IPv4 addresses need exactly four octets")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        lex(src).unwrap().into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn lexes_pipeline() {
        let k = kinds("conn | where dport==443 | stats count() by src | sort -count | head 10");
        assert_eq!(k[0], TokenKind::Ident("conn".into()));
        assert_eq!(k[1], TokenKind::Pipe);
        assert_eq!(k[4], TokenKind::EqEq);
        assert_eq!(k[5], TokenKind::Int(443));
        assert!(k.contains(&TokenKind::By));
        assert!(k.contains(&TokenKind::Minus));
        assert_eq!(*k.last().unwrap(), TokenKind::Eof);
    }

    #[test]
    fn spans_are_exact() {
        let src = "conn | where id.orig_h == 10.0.0.1";
        let toks = lex(src).unwrap();
        let ident = &toks[3];
        assert_eq!(ident.kind, TokenKind::Ident("id.orig_h".into()));
        assert_eq!(&src[ident.span.start..ident.span.end], "id.orig_h");
        let ip = &toks[5];
        assert_eq!(&src[ip.span.start..ip.span.end], "10.0.0.1");
    }

    #[test]
    fn literal_shapes() {
        let k = kinds("1 2.5 30s 1.5m 250ms 10.0.0.0/8 192.168.1.1 \"a\\\"b\" 'x' true null");
        assert_eq!(k[0], TokenKind::Int(1));
        assert_eq!(k[1], TokenKind::Float(2.5));
        assert_eq!(k[2], TokenKind::Duration(30_000_000));
        assert_eq!(k[3], TokenKind::Duration(90_000_000));
        assert_eq!(k[4], TokenKind::Duration(250_000));
        assert!(matches!(k[5], TokenKind::Cidr(_)));
        assert!(matches!(k[6], TokenKind::Ip(_)));
        assert_eq!(k[7], TokenKind::Str("a\"b".into()));
        assert_eq!(k[8], TokenKind::Str("x".into()));
        assert_eq!(k[9], TokenKind::True);
        assert_eq!(k[10], TokenKind::Null);
    }

    #[test]
    fn operators_and_comments() {
        let k = kinds("a <= b >= c < d > e != f =~ g !~ h = i % j # trailing\n// another\n;");
        assert!(k.contains(&TokenKind::Le));
        assert!(k.contains(&TokenKind::Ge));
        assert!(k.contains(&TokenKind::Lt));
        assert!(k.contains(&TokenKind::Gt));
        assert!(k.contains(&TokenKind::NotEq));
        assert!(k.contains(&TokenKind::Match));
        assert!(k.contains(&TokenKind::NotMatch));
        assert!(k.contains(&TokenKind::Eq));
        assert!(k.contains(&TokenKind::Percent));
        assert_eq!(k[k.len() - 2], TokenKind::Semi);
    }

    #[test]
    fn regex_escapes_are_preserved() {
        assert_eq!(
            kinds(r#""\d+\.exe""#)[0],
            TokenKind::Str(r"\d+\.exe".into())
        );
    }

    #[test]
    fn errors_have_spans() {
        let e = lex("conn | where x == \"oops").unwrap_err();
        assert_eq!(e.span.start, 18);
        assert!(e.message.contains("unterminated"));
        let e = lex("conn | where x == 1.2.3").unwrap_err();
        assert_eq!((e.span.start, e.span.end), (18, 23));
        let e = lex("conn | where 5q").unwrap_err();
        assert!(e.message.contains("invalid duration"));
        let e = lex("a ! b").unwrap_err();
        assert_eq!(e.span, Span::new(2, 3));
        let e = lex("a $ b").unwrap_err();
        assert!(e.message.contains('$'));
        assert!(lex("300.1.1.1").is_err());
        assert!(lex("99999999999999999999").is_err());
        assert!(lex("10.0.0.0/99").is_err());
        assert!(lex("\"abc\\").is_err());
    }

    #[test]
    fn display_round_trips_punctuation() {
        for t in [
            "|", ",", "(", ")", "[", "]", "+", "-", "*", "/", "==", "!=", "<=", ">=",
        ] {
            assert_eq!(kinds(t)[0].to_string(), t);
        }
        assert_eq!(TokenKind::Eof.describe(), "end of query");
        assert_eq!(TokenKind::Ident("x".into()).describe(), "identifier `x`");
    }
}
