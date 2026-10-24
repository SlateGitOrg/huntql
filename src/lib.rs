//! # huntql
//!
//! A pipe-based threat-hunting query language over Zeek logs.
//!
//! ```text
//! conn | where dport == 443 | stats count() by src | sort -count | head 10
//! conn | beacon min_score=0.7
//! http | rare user_agent by src
//! ```
//!
//! Pipeline: [`lexer`] -> [`parser`] (span-accurate [`diag::Diagnostic`]s)
//! -> [`ast`] -> [`planner`] (type checking, typed [`expr::TExpr`],
//! rewrites) -> [`plan::Plan`] -> [`exec`] (push-based streaming executor)
//! over [`zeek`] readers. [`beacon`] implements periodicity scoring,
//! [`gen`] the synthetic log generator and [`eval`] the held-out
//! beacon-detection evaluation.

pub mod ast;
pub mod beacon;
pub mod diag;
pub mod eval;
pub mod exec;
pub mod expr;
pub mod gen;
pub mod lexer;
pub mod output;
pub mod parser;
pub mod plan;
pub mod planner;
pub mod schema;
pub mod timefmt;
pub mod value;
pub mod zeek;

use std::io::Write;

pub use diag::{Diagnostic, Span};
pub use exec::{ExecError, ExecOptions, ExecStats};
pub use output::OutputFormat;
pub use plan::Plan;
pub use planner::{BuiltinSchemas, SchemaProvider};
pub use zeek::Catalog;

/// Any failure while compiling or running a query.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A lex/parse/plan error; render it with [`Diagnostic::render`].
    #[error("{0}")]
    Query(#[from] Diagnostic),
    #[error(transparent)]
    Exec(#[from] ExecError),
}

impl Error {
    /// Human-readable message, with a source snippet for query errors.
    pub fn render(&self, source: &str) -> String {
        match self {
            Error::Query(d) => d.render(source),
            Error::Exec(e) => format!("error: {e}"),
        }
    }
}

/// Parse and plan one query.
pub fn compile(source: &str, provider: &dyn SchemaProvider) -> Result<Plan, Diagnostic> {
    let query = parser::parse_query(source)?;
    planner::plan(&query, provider)
}

/// Compile and run a query against a catalog, writing formatted results.
pub fn run_query(
    source: &str,
    catalog: &Catalog,
    format: OutputFormat,
    out: Box<dyn Write + '_>,
    opts: ExecOptions,
) -> Result<ExecStats, Error> {
    let plan = compile(source, catalog)?;
    run_plan(&plan, catalog, format, out, opts)
}

/// Run an already-compiled plan.
pub fn run_plan(
    plan: &Plan,
    catalog: &Catalog,
    format: OutputFormat,
    out: Box<dyn Write + '_>,
    opts: ExecOptions,
) -> Result<ExecStats, Error> {
    let mut source = catalog.open_source(&plan.source)?;
    let mut sink = output::sink(format, plan.output_schema(), out);
    let stats = exec::execute(plan, &mut source, sink.as_mut(), opts)?;
    let c = source.counters();
    if c.bad_rows > 0 || c.bad_values > 0 {
        log::warn!(
            "{} malformed rows skipped, {} unparseable values read as null",
            c.bad_rows,
            c.bad_values
        );
    }
    Ok(stats)
}
