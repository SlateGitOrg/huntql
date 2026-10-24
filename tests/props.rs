//! Property-based tests (proptest).

use proptest::prelude::*;

use huntql::ast::{self, BinOp, Expr, ExprKind, Ident, Literal, Query, Stage, StageKind, UnOp};
use huntql::diag::{Diagnostic, Phase, Span};
use huntql::exec::{execute, CollectSink, ExecOptions, Row, VecSource};
use huntql::plan::{Plan, PlanOp, SortSpec, SourceSpec};
use huntql::schema::Schema;
use huntql::timefmt;
use huntql::value::{Type, Value};

fn ident(name: &str) -> Ident {
    Ident {
        name: name.to_string(),
        span: Span::default(),
    }
}

fn arb_field() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "src",
        "dst",
        "dport",
        "id.orig_h",
        "proto",
        "orig_bytes",
        "duration",
        "ts",
        "query",
    ])
    .prop_map(str::to_string)
}

fn arb_literal() -> impl Strategy<Value = Literal> {
    prop_oneof![
        Just(Literal::Null),
        any::<bool>().prop_map(Literal::Bool),
        (0i64..1_000_000).prop_map(Literal::Int),
        (0u32..100_000, 1u32..1000).prop_map(|(a, b)| Literal::Float(a as f64 + b as f64 / 1024.0)),
        "[a-z0-9 ./\\\\\"'-]{0,12}".prop_map(Literal::Str),
        (0i64..10_000_000_000).prop_map(Literal::Duration),
        any::<[u8; 4]>().prop_map(|o| Literal::Ip(std::net::IpAddr::from(o))),
        (any::<[u8; 4]>(), 0u8..=32).prop_map(|(o, p)| Literal::Cidr(huntql::value::Subnet {
            addr: std::net::IpAddr::from(o),
            prefix: p
        })),
    ]
}

fn expr(kind: ExprKind) -> Expr {
    Expr {
        kind,
        span: Span::default(),
    }
}

fn arb_expr() -> impl Strategy<Value = Expr> {
    let leaf = prop_oneof![
        arb_literal().prop_map(|l| expr(ExprKind::Literal(l))),
        arb_field().prop_map(|f| expr(ExprKind::Field(f))),
    ];
    leaf.prop_recursive(4, 32, 4, |inner| {
        let ops = prop::sample::select(vec![
            BinOp::Or,
            BinOp::And,
            BinOp::Eq,
            BinOp::NotEq,
            BinOp::Lt,
            BinOp::Le,
            BinOp::Gt,
            BinOp::Ge,
            BinOp::Match,
            BinOp::NotMatch,
            BinOp::Add,
            BinOp::Sub,
            BinOp::Mul,
            BinOp::Div,
            BinOp::Mod,
        ]);
        prop_oneof![
            (ops, inner.clone(), inner.clone()).prop_map(|(op, l, r)| expr(ExprKind::Binary(
                op,
                Box::new(l),
                Box::new(r)
            ))),
            inner
                .clone()
                .prop_map(|e| expr(ExprKind::Unary(UnOp::Not, Box::new(e)))),
            inner
                .clone()
                .prop_map(|e| expr(ExprKind::Unary(UnOp::Neg, Box::new(e)))),
            (
                inner.clone(),
                prop::collection::vec(inner.clone(), 0..3),
                any::<bool>()
            )
                .prop_map(|(e, list, negated)| expr(ExprKind::In {
                    expr: Box::new(e),
                    list,
                    negated
                })),
            (
                prop::sample::select(vec!["len", "lower", "coalesce", "bin"]),
                prop::collection::vec(inner, 0..3)
            )
                .prop_map(|(f, args)| expr(ExprKind::Call(ident(f), args))),
        ]
    })
}

fn arb_fields() -> impl Strategy<Value = Vec<Ident>> {
    prop::collection::vec(arb_field().prop_map(|f| ident(&f)), 1..3)
}

fn arb_opts() -> impl Strategy<Value = Vec<ast::Opt>> {
    prop::collection::vec(
        (
            prop::sample::select(vec!["limit", "min_count", "baseline"]),
            arb_literal(),
        )
            .prop_filter_map("option literal", |(n, v)| match v {
                Literal::Int(_)
                | Literal::Float(_)
                | Literal::Duration(_)
                | Literal::Bool(_)
                | Literal::Str(_) => Some(ast::Opt {
                    name: ident(n),
                    value: v,
                    span: Span::default(),
                }),
                _ => None,
            }),
        0..2,
    )
}

fn arb_stage() -> impl Strategy<Value = StageKind> {
    prop_oneof![
        arb_expr().prop_map(StageKind::Where),
        (any::<bool>(), arb_fields())
            .prop_map(|(exclude, fields)| StageKind::Fields { exclude, fields }),
        prop::collection::vec((arb_field().prop_map(|f| ident(&f)), arb_expr()), 1..3)
            .prop_map(StageKind::Eval),
        (arb_fields(), arb_expr()).prop_map(|(by, e)| StageKind::Stats {
            aggs: vec![ast::Agg {
                func: ident("sum"),
                arg: Some(e),
                alias: Some(ident("total")),
                span: Span::default()
            }],
            by
        }),
        (arb_fields(), any::<bool>()).prop_map(|(f, d)| StageKind::Sort(
            f.into_iter()
                .map(|field| ast::SortKey {
                    field,
                    descending: d
                })
                .collect()
        )),
        (0u64..1000).prop_map(StageKind::Head),
        (0u64..1000).prop_map(StageKind::Tail),
        arb_fields().prop_map(StageKind::Dedup),
        (arb_fields(), arb_opts()).prop_map(|(fields, opts)| StageKind::Stack { fields, opts }),
        (arb_fields(), arb_opts()).prop_map(|(by, opts)| StageKind::Beacon { by, opts }),
        (arb_fields(), arb_opts()).prop_map(|(fields, opts)| StageKind::FirstSeen { fields, opts }),
    ]
}

fn arb_query() -> impl Strategy<Value = Query> {
    (
        prop::sample::select(vec!["conn", "dns", "http", "ssl"]),
        prop::collection::vec(arb_stage(), 0..5),
    )
        .prop_map(|(src, stages)| Query {
            source: ident(src),
            stages: stages
                .into_iter()
                .map(|kind| Stage {
                    kind,
                    name_span: Span::default(),
                    span: Span::default(),
                })
                .collect(),
            span: Span::default(),
        })
}

fn int_rows() -> impl Strategy<Value = Vec<Row>> {
    prop::collection::vec(
        (0i64..20, prop::option::of(0i64..5))
            .prop_map(|(a, b)| vec![Value::Int(a), b.map_or(Value::Null, Value::Int)]),
        0..200,
    )
}

fn two_col_schema() -> Schema {
    let mut s = Schema::default();
    s.push("a", Type::Int);
    s.push("b", Type::Int);
    s
}

fn manual_plan(ops: Vec<PlanOp>) -> Plan {
    let schema = two_col_schema();
    Plan {
        source: SourceSpec {
            log: "mem".into(),
            schema: schema.clone(),
            needed: None,
        },
        ops: ops.into_iter().map(|o| (o, schema.clone())).collect(),
        notes: vec![],
    }
}

fn run(plan: &Plan, rows: Vec<Row>) -> (Vec<Row>, huntql::ExecStats) {
    let mut sink = CollectSink::default();
    let stats = execute(
        plan,
        &mut VecSource::new(rows),
        &mut sink,
        ExecOptions::default(),
    )
    .unwrap();
    (sink.rows, stats)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The lexer and parser never panic, whatever the input.
    #[test]
    fn parser_total_on_arbitrary_input(src in "\\PC{0,80}") {
        let _ = huntql::parser::parse_query(&src);
        let _ = huntql::parser::parse_script(&src);
    }

    /// Token-soup inputs exercise deeper parser paths without panicking, and
    /// every error span lies inside the source.
    #[test]
    fn parser_errors_have_valid_spans(parts in prop::collection::vec(prop::sample::select(vec![
        "conn", "|", "where", "stats", "by", "count()", "sort", "-", "head", "10", "==", "\"x\"", "(", ")",
        "[", "]", ",", "and", "not", "in", "10.0.0.0/8", "5m", "beacon", "min_count=", "=", "eval", "x",
    ]), 0..14)) {
        let src = parts.join(" ");
        if let Err(d) = huntql::parser::parse_query(&src) {
            prop_assert!(d.span.start <= d.span.end && d.span.end <= src.len(), "{d:?}");
            let _ = d.render(&src);
        }
    }

    /// Pretty-printing is a fixed point: parse(print(q)) prints identically.
    #[test]
    fn ast_print_parse_round_trip(q in arb_query()) {
        let printed = q.to_string();
        let reparsed = huntql::parser::parse_query(&printed)
            .unwrap_or_else(|d| panic!("{}\n{}", printed, d.render(&printed)));
        prop_assert_eq!(reparsed.to_string(), printed);
    }

    /// Planning never panics on generated (often ill-typed) queries.
    #[test]
    fn planner_total(q in arb_query()) {
        let _ = huntql::planner::plan(&q, &huntql::BuiltinSchemas);
    }

    /// The fused top-k heap returns exactly what a stable sort + head does,
    /// while holding at most k rows.
    #[test]
    fn topk_equals_sort_then_head(rows in int_rows(), k in 0u64..30, desc_a in any::<bool>(), desc_b in any::<bool>()) {
        let keys = vec![SortSpec { col: 0, descending: desc_a }, SortSpec { col: 1, descending: desc_b }];
        let (sorted, _) = run(&manual_plan(vec![PlanOp::Sort(keys.clone()), PlanOp::Head(k)]), rows.clone());
        let (topk, stats) = run(&manual_plan(vec![PlanOp::TopK { keys, k }]), rows);
        prop_assert_eq!(sorted, topk);
        prop_assert!(stats.peak_state as u64 <= k);
    }

    /// Streaming pipelines retain nothing; tail retains at most n rows.
    #[test]
    fn streaming_memory_is_bounded(rows in int_rows(), n in 0u64..10) {
        let filter = huntql::expr::TExpr::new(
            huntql::expr::TExprKind::Cmp(
                huntql::expr::CmpOp::Gt,
                Box::new(huntql::expr::TExpr::new(huntql::expr::TExprKind::Col(0), Type::Int)),
                Box::new(huntql::expr::TExpr::constant(Value::Int(5))),
            ),
            Type::Bool,
        );
        let total = rows.len();
        let (_, stats) = run(&manual_plan(vec![PlanOp::Filter(filter), PlanOp::Head(1_000_000)]), rows.clone());
        prop_assert_eq!(stats.peak_state, 0);
        let (out, stats) = run(&manual_plan(vec![PlanOp::Tail(n)]), rows);
        prop_assert!(stats.peak_state as u64 <= n);
        prop_assert_eq!(out.len(), total.min(n as usize));
    }

    /// Group counts from `stats` add up to the input size; `stack`
    /// percentages are cumulative and end at 100.
    #[test]
    fn aggregation_invariants(rows in int_rows()) {
        let total = rows.len() as i64;
        let plan = huntql::planner::plan(
            &huntql::parser::parse_query("mem | stats count() as n, sum(a) as s by b").unwrap(),
            &MemSchema,
        ).unwrap();
        let (out, _) = run(&plan, rows.clone());
        prop_assert_eq!(out.iter().map(|r| match r[1] { Value::Int(n) => n, _ => 0 }).sum::<i64>(), total);
        let plan = huntql::planner::plan(&huntql::parser::parse_query("mem | stack a").unwrap(), &MemSchema).unwrap();
        let (out, _) = run(&plan, rows);
        if let Some(last) = out.last() {
            prop_assert!((last[3].as_f64().unwrap() - 100.0).abs() < 1e-6);
        }
        let counts: Vec<i64> = out.iter().map(|r| match r[1] { Value::Int(n) => n, _ => 0 }).collect();
        prop_assert!(counts.windows(2).all(|w| w[0] <= w[1]), "long tail first");
    }

    /// Timestamp formatting and parsing are inverses.
    #[test]
    fn time_round_trips(us in -2_000_000_000_000_000i64..4_000_000_000_000_000i64) {
        prop_assert_eq!(timefmt::parse_iso(&timefmt::format_iso(us)), Some(us));
        prop_assert_eq!(timefmt::parse_seconds_to_micros(&timefmt::format_epoch(us)), Some(us));
    }

    /// Rendering a diagnostic never panics for any in-bounds span, even on
    /// multi-byte text.
    #[test]
    fn diagnostics_render_any_span(src in "\\PC{0,40}", a in 0usize..60, b in 0usize..60) {
        let (lo, hi) = (a.min(b).min(src.len()), a.max(b).min(src.len()));
        let d = Diagnostic::new(Phase::Plan, "x", Span::new(lo, hi)).with_label("l").with_help("h");
        let r = d.render(&src);
        prop_assert!(r.starts_with("error[plan]: x"));
    }
}

/// Two-column in-memory schema for planner-based properties.
struct MemSchema;

impl huntql::SchemaProvider for MemSchema {
    fn schema(&self, log: &str) -> Option<Schema> {
        (log == "mem").then(two_col_schema)
    }
    fn logs(&self) -> Vec<String> {
        vec!["mem".into()]
    }
}
