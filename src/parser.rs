//! Recursive-descent parser: tokens -> [`ast::Query`].
//!
//! Grammar (EBNF):
//!
//! ```text
//! query    = source { "|" stage } ;
//! source   = IDENT ;
//! stage    = "where" expr
//!          | "fields" [ "-" ] idents
//!          | "eval" IDENT "=" expr { "," IDENT "=" expr }
//!          | "rename" IDENT "as" IDENT { "," IDENT "as" IDENT }
//!          | "stats" agg { "," agg } [ "by" idents ]
//!          | "sort" key { "," key }            key = [ "-" | "+" ] IDENT
//!          | "head" [ INT ] | "tail" [ INT ]
//!          | "dedup" idents
//!          | "stack" idents opts
//!          | "rare" IDENT [ "by" idents ] opts
//!          | "first_seen" idents opts
//!          | "beacon" opts [ "by" idents ] opts ;
//! agg      = IDENT "(" [ expr ] ")" [ "as" IDENT ] ;
//! opts     = { IDENT "=" literal } ;
//! expr     = or ;
//! or       = and { "or" and } ;
//! and      = not { "and" not } ;
//! not      = "not" not | cmp ;
//! cmp      = add [ ( "==" | "!=" | "<" | "<=" | ">" | ">=" | "=~" | "!~" ) add
//!                | [ "not" ] "in" ( list | primary ) ] ;
//! add      = mul { ( "+" | "-" ) mul } ;
//! mul      = unary { ( "*" | "/" | "%" ) unary } ;
//! unary    = "-" unary | primary ;
//! primary  = literal | IDENT [ "(" [ expr { "," expr } ] ")" ] | "(" expr ")" | list ;
//! list     = "[" [ expr { "," expr } ] "]" ;
//! ```
//!
//! `&&`/`||` are deliberately not supported; the error message suggests the
//! keyword forms. Multiple queries in one file are separated by `;`.

use crate::ast::*;
use crate::diag::{Diagnostic, Phase, Span};
use crate::lexer::{lex, Token, TokenKind};

/// Operator names accepted after `|`.
pub const STAGE_NAMES: &[&str] = &[
    "where",
    "fields",
    "eval",
    "rename",
    "stats",
    "sort",
    "head",
    "tail",
    "dedup",
    "stack",
    "rare",
    "first_seen",
    "beacon",
];

/// Parse exactly one query.
pub fn parse_query(src: &str) -> Result<Query, Diagnostic> {
    let tokens = lex(src)?;
    let mut p = Parser { tokens, pos: 0 };
    let q = p.query()?;
    p.expect_eof()?;
    Ok(q)
}

/// Parse a script of `;`-separated queries (empty statements are skipped).
pub fn parse_script(src: &str) -> Result<Vec<Query>, Diagnostic> {
    let tokens = lex(src)?;
    let mut p = Parser { tokens, pos: 0 };
    let mut out = Vec::new();
    loop {
        while p.eat(&TokenKind::Semi) {}
        if p.at(&TokenKind::Eof) {
            return Ok(out);
        }
        out.push(p.query()?);
        if !p.at(&TokenKind::Eof) {
            p.expect(&TokenKind::Semi, "`;` between queries")?;
        }
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

type PResult<T> = Result<T, Diagnostic>;

impl Parser {
    fn peek(&self) -> &Token {
        &self.tokens[self.pos.min(self.tokens.len() - 1)]
    }

    fn peek_kind(&self) -> &TokenKind {
        &self.peek().kind
    }

    fn peek_nth(&self, n: usize) -> &TokenKind {
        &self.tokens[(self.pos + n).min(self.tokens.len() - 1)].kind
    }

    fn advance(&mut self) -> Token {
        let t = self.peek().clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        t
    }

    fn at(&self, k: &TokenKind) -> bool {
        self.peek_kind() == k
    }

    fn eat(&mut self, k: &TokenKind) -> bool {
        if self.at(k) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn prev_end(&self) -> usize {
        if self.pos == 0 {
            0
        } else {
            self.tokens[self.pos - 1].span.end
        }
    }

    fn error_here(&self, expected: &str) -> Diagnostic {
        let t = self.peek();
        Diagnostic::new(
            Phase::Parse,
            format!("expected {expected}, found {}", t.kind.describe()),
            t.span,
        )
    }

    fn expect(&mut self, k: &TokenKind, what: &str) -> PResult<Token> {
        if self.at(k) {
            Ok(self.advance())
        } else {
            Err(self.error_here(what))
        }
    }

    fn expect_eof(&mut self) -> PResult<()> {
        if self.at(&TokenKind::Eof) {
            return Ok(());
        }
        let mut d = self.error_here("`|` or end of query");
        if let TokenKind::Ident(name) = self.peek_kind() {
            if STAGE_NAMES.contains(&name.as_str()) {
                d = d.with_help(format!("did you forget a `|` before `{name}`?"));
            }
        }
        Err(d)
    }

    fn ident(&mut self, what: &str) -> PResult<Ident> {
        match self.peek_kind().clone() {
            TokenKind::Ident(name) => {
                let t = self.advance();
                Ok(Ident { name, span: t.span })
            }
            _ => Err(self.error_here(what)),
        }
    }

    fn ident_list(&mut self, what: &str) -> PResult<Vec<Ident>> {
        let mut out = vec![self.ident(what)?];
        while self.eat(&TokenKind::Comma) {
            out.push(self.ident(what)?);
        }
        Ok(out)
    }

    fn query(&mut self) -> PResult<Query> {
        let source = match self.peek_kind() {
            TokenKind::Ident(_) => self.ident("a log source")?,
            _ => {
                return Err(self.error_here("a log source").with_help(
                    "queries start with a log name such as `conn`, `dns`, `http` or `ssl`",
                ))
            }
        };
        let mut stages = Vec::new();
        while self.eat(&TokenKind::Pipe) {
            stages.push(self.stage()?);
        }
        let span = source.span.to(Span::new(self.prev_end(), self.prev_end()));
        Ok(Query {
            source,
            stages,
            span,
        })
    }

    fn stage(&mut self) -> PResult<Stage> {
        let name = match self.peek_kind() {
            TokenKind::Ident(_) => self.ident("an operator")?,
            _ => {
                return Err(self
                    .error_here("an operator after `|`")
                    .with_help(format!("operators: {}", STAGE_NAMES.join(", "))))
            }
        };
        let kind = match name.name.as_str() {
            "where" => StageKind::Where(self.expr()?),
            "fields" => {
                let exclude = self.eat(&TokenKind::Minus);
                StageKind::Fields {
                    exclude,
                    fields: self.ident_list("a field name")?,
                }
            }
            "eval" => {
                let mut assigns = Vec::new();
                loop {
                    let target = self.ident("a new field name")?;
                    if !self.at(&TokenKind::Eq) {
                        let mut d = self.error_here("`=`");
                        if self.at(&TokenKind::EqEq) {
                            d = d.with_help("eval assigns with a single `=`");
                        }
                        return Err(d);
                    }
                    self.advance();
                    assigns.push((target, self.expr()?));
                    if !self.eat(&TokenKind::Comma) {
                        break;
                    }
                }
                StageKind::Eval(assigns)
            }
            "rename" => {
                let mut pairs = Vec::new();
                loop {
                    let from = self.ident("a field name")?;
                    self.expect(&TokenKind::As, "`as`")?;
                    let to = self.ident("a new field name")?;
                    pairs.push((from, to));
                    if !self.eat(&TokenKind::Comma) {
                        break;
                    }
                }
                StageKind::Rename(pairs)
            }
            "stats" => {
                let mut aggs = vec![self.agg()?];
                while self.eat(&TokenKind::Comma) {
                    aggs.push(self.agg()?);
                }
                let by = if self.eat(&TokenKind::By) {
                    self.ident_list("a group-by field")?
                } else {
                    Vec::new()
                };
                StageKind::Stats { aggs, by }
            }
            "sort" => {
                let mut keys = Vec::new();
                loop {
                    let descending = if self.eat(&TokenKind::Minus) {
                        true
                    } else {
                        self.eat(&TokenKind::Plus);
                        false
                    };
                    keys.push(SortKey {
                        field: self.ident("a sort field")?,
                        descending,
                    });
                    if !self.eat(&TokenKind::Comma) {
                        break;
                    }
                }
                StageKind::Sort(keys)
            }
            "head" => StageKind::Head(self.opt_count(10)?),
            "tail" => StageKind::Tail(self.opt_count(10)?),
            "dedup" => StageKind::Dedup(self.ident_list("a field name")?),
            "stack" => {
                let fields = self.ident_list("a field to stack")?;
                StageKind::Stack {
                    fields,
                    opts: self.opts()?,
                }
            }
            "rare" => {
                let field = self.ident("a field")?;
                let by = if self.eat(&TokenKind::By) {
                    self.ident_list("an entity field")?
                } else {
                    Vec::new()
                };
                StageKind::Rare {
                    field,
                    by,
                    opts: self.opts()?,
                }
            }
            "first_seen" => {
                let fields = self.ident_list("a key field")?;
                StageKind::FirstSeen {
                    fields,
                    opts: self.opts()?,
                }
            }
            "beacon" => {
                let mut opts = self.opts()?;
                let by = if self.eat(&TokenKind::By) {
                    self.ident_list("a grouping field")?
                } else {
                    Vec::new()
                };
                opts.extend(self.opts()?);
                StageKind::Beacon { by, opts }
            }
            other => {
                let mut d = Diagnostic::new(
                    Phase::Parse,
                    format!("unknown operator `{other}`"),
                    name.span,
                );
                if let Some(s) = crate::diag::suggest(other, STAGE_NAMES.iter().copied()) {
                    d = d.with_label(format!("did you mean `{s}`?"));
                } else {
                    d = d.with_help(format!("operators: {}", STAGE_NAMES.join(", ")));
                }
                return Err(d);
            }
        };
        Ok(Stage {
            kind,
            name_span: name.span,
            span: name.span.to(Span::new(self.prev_end(), self.prev_end())),
        })
    }

    fn opt_count(&mut self, default: u64) -> PResult<u64> {
        match *self.peek_kind() {
            TokenKind::Int(n) => {
                let t = self.advance();
                u64::try_from(n).map_err(|_| {
                    Diagnostic::new(Phase::Parse, "row count must be non-negative", t.span)
                })
            }
            TokenKind::Minus => Err(self.error_here("a non-negative row count")),
            _ => Ok(default),
        }
    }

    fn opts(&mut self) -> PResult<Vec<Opt>> {
        let mut out = Vec::new();
        while matches!(self.peek_kind(), TokenKind::Ident(_)) && self.peek_nth(1) == &TokenKind::Eq
        {
            let name = self.ident("an option name")?;
            self.advance(); // `=`
            let t = self.advance();
            let value = match t.kind {
                TokenKind::Int(i) => Literal::Int(i),
                TokenKind::Float(f) => Literal::Float(f),
                TokenKind::Duration(d) => Literal::Duration(d),
                TokenKind::Str(s) => Literal::Str(s),
                TokenKind::True => Literal::Bool(true),
                TokenKind::False => Literal::Bool(false),
                other => {
                    return Err(Diagnostic::new(
                        Phase::Parse,
                        format!(
                            "expected a literal option value, found {}",
                            other.describe()
                        ),
                        t.span,
                    ))
                }
            };
            out.push(Opt {
                span: name.span.to(t.span),
                name,
                value,
            });
        }
        Ok(out)
    }

    fn agg(&mut self) -> PResult<Agg> {
        let func = self.ident("an aggregation such as `count()`")?;
        if !self.at(&TokenKind::LParen) {
            return Err(self.error_here("`(`").with_help(format!(
                "aggregations are called like functions: `{}()`",
                func.name
            )));
        }
        self.advance();
        let arg = if self.at(&TokenKind::RParen) {
            None
        } else {
            Some(self.expr()?)
        };
        self.expect(&TokenKind::RParen, "`)`")?;
        let alias = if self.eat(&TokenKind::As) {
            Some(self.ident("an alias")?)
        } else {
            None
        };
        Ok(Agg {
            span: func.span.to(Span::new(self.prev_end(), self.prev_end())),
            func,
            arg,
            alias,
        })
    }

    // -- expressions --------------------------------------------------------

    pub fn expr(&mut self) -> PResult<Expr> {
        self.or_expr()
    }

    fn binary(op: BinOp, l: Expr, r: Expr) -> Expr {
        Expr {
            span: l.span.to(r.span),
            kind: ExprKind::Binary(op, Box::new(l), Box::new(r)),
        }
    }

    fn or_expr(&mut self) -> PResult<Expr> {
        let mut l = self.and_expr()?;
        while self.eat(&TokenKind::Or) {
            let r = self.and_expr()?;
            l = Self::binary(BinOp::Or, l, r);
        }
        Ok(l)
    }

    fn and_expr(&mut self) -> PResult<Expr> {
        let mut l = self.not_expr()?;
        while self.eat(&TokenKind::And) {
            let r = self.not_expr()?;
            l = Self::binary(BinOp::And, l, r);
        }
        Ok(l)
    }

    fn not_expr(&mut self) -> PResult<Expr> {
        if self.at(&TokenKind::Not) {
            let t = self.advance();
            let inner = self.not_expr()?;
            return Ok(Expr {
                span: t.span.to(inner.span),
                kind: ExprKind::Unary(UnOp::Not, Box::new(inner)),
            });
        }
        self.cmp_expr()
    }

    fn cmp_expr(&mut self) -> PResult<Expr> {
        let l = self.add_expr()?;
        let op = match self.peek_kind() {
            TokenKind::EqEq => BinOp::Eq,
            TokenKind::NotEq => BinOp::NotEq,
            TokenKind::Lt => BinOp::Lt,
            TokenKind::Le => BinOp::Le,
            TokenKind::Gt => BinOp::Gt,
            TokenKind::Ge => BinOp::Ge,
            TokenKind::Match => BinOp::Match,
            TokenKind::NotMatch => BinOp::NotMatch,
            TokenKind::Eq => {
                return Err(self
                    .error_here("a comparison operator")
                    .with_help("use `==` to compare values"))
            }
            TokenKind::In => return self.in_expr(l, false),
            TokenKind::Not if self.peek_nth(1) == &TokenKind::In => {
                self.advance();
                return self.in_expr(l, true);
            }
            _ => return Ok(l),
        };
        self.advance();
        let r = self.add_expr()?;
        Ok(Self::binary(op, l, r))
    }

    fn in_expr(&mut self, l: Expr, negated: bool) -> PResult<Expr> {
        self.advance(); // `in`
        let (list, end) = if self.at(&TokenKind::LBracket) {
            let open = self.advance();
            let items = self.expr_list(&TokenKind::RBracket)?;
            let close = self.expect(&TokenKind::RBracket, "`]`")?;
            let _ = open;
            (items, close.span)
        } else {
            let single = self.primary()?;
            let sp = single.span;
            (vec![single], sp)
        };
        Ok(Expr {
            span: l.span.to(end),
            kind: ExprKind::In {
                expr: Box::new(l),
                list,
                negated,
            },
        })
    }

    fn expr_list(&mut self, close: &TokenKind) -> PResult<Vec<Expr>> {
        let mut items = Vec::new();
        if self.at(close) {
            return Ok(items);
        }
        loop {
            items.push(self.expr()?);
            if !self.eat(&TokenKind::Comma) {
                return Ok(items);
            }
        }
    }

    fn add_expr(&mut self) -> PResult<Expr> {
        let mut l = self.mul_expr()?;
        loop {
            let op = match self.peek_kind() {
                TokenKind::Plus => BinOp::Add,
                TokenKind::Minus => BinOp::Sub,
                _ => return Ok(l),
            };
            self.advance();
            let r = self.mul_expr()?;
            l = Self::binary(op, l, r);
        }
    }

    fn mul_expr(&mut self) -> PResult<Expr> {
        let mut l = self.unary_expr()?;
        loop {
            let op = match self.peek_kind() {
                TokenKind::Star => BinOp::Mul,
                TokenKind::Slash => BinOp::Div,
                TokenKind::Percent => BinOp::Mod,
                _ => return Ok(l),
            };
            self.advance();
            let r = self.unary_expr()?;
            l = Self::binary(op, l, r);
        }
    }

    fn unary_expr(&mut self) -> PResult<Expr> {
        if self.at(&TokenKind::Minus) {
            let t = self.advance();
            let inner = self.unary_expr()?;
            return Ok(Expr {
                span: t.span.to(inner.span),
                kind: ExprKind::Unary(UnOp::Neg, Box::new(inner)),
            });
        }
        self.primary()
    }

    fn primary(&mut self) -> PResult<Expr> {
        let t = self.peek().clone();
        let lit = |l: Literal| ExprKind::Literal(l);
        let kind = match t.kind {
            TokenKind::Int(i) => lit(Literal::Int(i)),
            TokenKind::Float(f) => lit(Literal::Float(f)),
            TokenKind::Str(s) => lit(Literal::Str(s)),
            TokenKind::Duration(d) => lit(Literal::Duration(d)),
            TokenKind::Ip(ip) => lit(Literal::Ip(ip)),
            TokenKind::Cidr(c) => lit(Literal::Cidr(c)),
            TokenKind::True => lit(Literal::Bool(true)),
            TokenKind::False => lit(Literal::Bool(false)),
            TokenKind::Null => lit(Literal::Null),
            TokenKind::Ident(name) => {
                self.advance();
                if self.at(&TokenKind::LParen) {
                    self.advance();
                    let args = self.expr_list(&TokenKind::RParen)?;
                    let close = self.expect(&TokenKind::RParen, "`)` to close the call")?;
                    return Ok(Expr {
                        span: t.span.to(close.span),
                        kind: ExprKind::Call(Ident { name, span: t.span }, args),
                    });
                }
                return Ok(Expr {
                    kind: ExprKind::Field(name),
                    span: t.span,
                });
            }
            TokenKind::LParen => {
                self.advance();
                let mut inner = self.expr()?;
                let close = self.expect(&TokenKind::RParen, "`)`")?;
                inner.span = t.span.to(close.span);
                return Ok(inner);
            }
            TokenKind::LBracket => {
                return Err(Diagnostic::new(
                    Phase::Parse,
                    "list literals are only allowed after `in`",
                    t.span,
                ))
            }
            TokenKind::Pipe if self.pos > 0 => {
                return Err(self
                    .error_here("an expression")
                    .with_help("the previous operator needs an argument before the next `|`"))
            }
            _ => return Err(self.error_here("an expression")),
        };
        self.advance();
        Ok(Expr { kind, span: t.span })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(src: &str) -> Query {
        parse_query(src).unwrap_or_else(|e| panic!("{}", e.render(src)))
    }

    fn err(src: &str) -> Diagnostic {
        parse_query(src).unwrap_err()
    }

    #[test]
    fn parses_canonical_example() {
        let q = p("conn | where dport==443 | stats count() by src | sort -count | head 10");
        assert_eq!(q.source.name, "conn");
        assert_eq!(q.stages.len(), 4);
        assert!(matches!(q.stages[3].kind, StageKind::Head(10)));
        assert_eq!(
            q.to_string(),
            "conn | where (dport == 443) | stats count() by src | sort -count | head 10"
        );
    }

    #[test]
    fn precedence() {
        let q = p("conn | where a == 1 or b == 2 and not c > 3 + 4 * 5");
        assert_eq!(
            q.stages[0].to_string(),
            "where ((a == 1) or ((b == 2) and (not (c > (3 + (4 * 5))))))"
        );
        let q = p("conn | where -x - -2 < 1");
        assert_eq!(q.stages[0].to_string(), "where (((-x) - (-2)) < 1)");
    }

    #[test]
    fn in_lists_and_calls() {
        let q = p(
            "conn | where src not in [10.0.0.1, 10.0.0.2] and dst in 10.0.0.0/8 and len(uid) > 3",
        );
        assert_eq!(
            q.stages[0].to_string(),
            "where (((src not in [10.0.0.1, 10.0.0.2]) and (dst in [10.0.0.0/8])) and (len(uid) > 3))"
        );
    }

    #[test]
    fn all_operators_round_trip() {
        let src = "conn | fields - uid, history | eval kb = orig_bytes / 1024, big = kb > 10 \
                   | rename src as client | stats count() as n, avg(duration) by client, dport \
                   | sort -n, +client | tail 5 | dedup client | head";
        let q = p(src);
        let printed = q.to_string();
        assert_eq!(p(&printed).to_string(), printed);
        assert!(matches!(q.stages.last().unwrap().kind, StageKind::Head(10)));
        let hunts = "ssl | stack server_name, version limit=20 | rare server_name by src limit=5 \
                     | first_seen query baseline=6h | beacon min_count=8 by src, dst min_score=0.5";
        let q = p(hunts);
        assert_eq!(q.stages.len(), 4);
        if let StageKind::Beacon { by, opts } = &q.stages[3].kind {
            assert_eq!(by.len(), 2);
            assert_eq!(opts.len(), 2);
        } else {
            panic!("expected beacon");
        }
        let _ = p(&q.to_string());
    }

    #[test]
    fn spans_point_at_source() {
        let src = "conn | stats avg(duration) as d by src";
        let q = p(src);
        let StageKind::Stats { aggs, by } = &q.stages[0].kind else {
            panic!()
        };
        let a = &aggs[0];
        assert_eq!(&src[a.span.start..a.span.end], "avg(duration) as d");
        assert_eq!(&src[by[0].span.start..by[0].span.end], "src");
        assert_eq!(
            &src[q.stages[0].name_span.start..q.stages[0].name_span.end],
            "stats"
        );
        assert_eq!(
            &src[q.stages[0].span.start..q.stages[0].span.end],
            "stats avg(duration) as d by src"
        );
    }

    #[test]
    fn scripts() {
        let qs = parse_script("conn | head 1;\n# comment\ndns | head 2;;").unwrap();
        assert_eq!(qs.len(), 2);
        assert!(parse_script("conn | head 1 dns").is_err());
        assert!(parse_script("").unwrap().is_empty());
    }

    #[test]
    fn error_messages() {
        let e = err("conn | wehre x == 1");
        assert!(e.label.as_deref() == Some("did you mean `where`?"), "{e:?}");
        assert_eq!(e.span, Span::new(7, 12));

        let e = err("conn | where x = 1");
        assert!(e.help.as_deref().unwrap().contains("=="));

        let e = err("conn | where x == 1 head 5");
        assert!(e.help.as_deref().unwrap().contains("forget a `|`"));

        let e = err("conn | where | head");
        assert!(e.message.contains("expected an expression"));

        let e = err("conn | stats count by src");
        assert!(e.help.unwrap().contains("count()"));

        let e = err("conn | eval x == 1");
        assert!(e.help.unwrap().contains("single `=`"));

        let e = err("| head");
        assert!(e.help.unwrap().contains("log name"));

        let e = err("conn | 5");
        assert!(e.message.contains("operator"));

        let e = err("conn | head -5");
        assert!(e.message.contains("non-negative"));

        let e = err("conn | where x == [1]");
        assert!(e.message.contains("list literals"));

        let e = err("conn | zzzzzzzz");
        assert!(e.help.unwrap().contains("operators:"));

        let e = err("conn | beacon min_count=src");
        assert!(e.message.contains("literal option value"));

        let e = err("conn | where (a == 1");
        assert!(e.message.contains("`)`"));

        let e = err("conn | rename a b");
        assert!(e.message.contains("`as`"));
    }

    #[test]
    fn options_and_bools() {
        let q = p("conn | stack a flag=true other=false s=\"x\" d=5m f=0.5");
        let StageKind::Stack { opts, .. } = &q.stages[0].kind else {
            panic!()
        };
        assert_eq!(opts.len(), 5);
        assert_eq!(
            q.stages[0].to_string(),
            "stack a flag=true other=false s=\"x\" d=300000000us f=0.5"
        );
    }
}
