//! Line-oriented REPL. Reads queries from any `BufRead` (a terminal or a
//! pipe), so it is fully scriptable and testable. A line ending in `|`
//! continues the query on the next line.

use std::io::{self, BufRead, Write};

use crate::exec::ExecOptions;
use crate::expr::FUNCTIONS;
use crate::output::OutputFormat;
use crate::parser::STAGE_NAMES;
use crate::plan::AggFunc;
use crate::planner::SchemaProvider;
use crate::zeek::Catalog;

const HELP: &str = "\
Enter a query, e.g.   conn | where dport == 443 | stats count() by src | sort -count | head 10
A line ending in `|` continues on the next line.

Commands:
  .help                  this text
  .logs                  log sources and the files behind them
  .schema <log>          columns and types of a log
  .explain <query>       show the physical plan without running it
  .format table|tsv|json output format
  .stats on|off          print execution statistics after each query
  .functions             scalar functions and aggregations
  .quit                  leave
";

pub struct Repl {
    pub catalog: Catalog,
    pub format: OutputFormat,
    pub show_stats: bool,
    pub opts: ExecOptions,
}

impl Repl {
    pub fn new(catalog: Catalog) -> Self {
        Repl {
            catalog,
            format: OutputFormat::Table,
            show_stats: false,
            opts: ExecOptions::default(),
        }
    }

    /// Run until end of input or `.quit`. Returns the number of queries that
    /// failed (useful as an exit status for scripted use).
    pub fn run(
        &mut self,
        input: &mut dyn BufRead,
        out: &mut dyn Write,
        interactive: bool,
    ) -> io::Result<usize> {
        let mut failures = 0;
        let mut pending = String::new();
        let mut line = String::new();
        loop {
            if interactive {
                write!(
                    out,
                    "{}",
                    if pending.is_empty() {
                        "huntql> "
                    } else {
                        "   ...> "
                    }
                )?;
                out.flush()?;
            }
            line.clear();
            if input.read_line(&mut line)? == 0 {
                break;
            }
            let trimmed = line.trim();
            if pending.is_empty() && trimmed.starts_with('.') {
                match self.command(trimmed, out)? {
                    Some(true) => break,
                    Some(false) => failures += 1,
                    None => {}
                }
                continue;
            }
            if trimmed.is_empty() && pending.is_empty() {
                continue;
            }
            pending.push_str(&line);
            if trimmed.ends_with('|') {
                continue;
            }
            let query = std::mem::take(&mut pending);
            let query = query.trim().trim_end_matches(';');
            if query.is_empty() {
                continue;
            }
            if !self.query(query, out)? {
                failures += 1;
            }
        }
        Ok(failures)
    }

    fn query(&mut self, query: &str, out: &mut dyn Write) -> io::Result<bool> {
        match crate::run_query(
            query,
            &self.catalog,
            self.format,
            Box::new(&mut *out),
            self.opts,
        ) {
            Ok(stats) => {
                if self.show_stats {
                    writeln!(out, "-- {stats}")?;
                }
                Ok(true)
            }
            Err(e) => {
                writeln!(out, "{}", e.render(query))?;
                Ok(false)
            }
        }
    }

    /// Handle a dot-command. `Some(true)` = quit, `Some(false)` = failed.
    fn command(&mut self, cmd: &str, out: &mut dyn Write) -> io::Result<Option<bool>> {
        let (name, arg) = cmd.split_once(char::is_whitespace).unwrap_or((cmd, ""));
        let arg = arg.trim();
        match name {
            ".quit" | ".exit" => return Ok(Some(true)),
            ".help" => write!(out, "{HELP}")?,
            ".logs" => {
                for log in self.catalog.logs() {
                    let files = self.catalog.files(&log);
                    let list: Vec<String> = files.iter().map(|f| f.display().to_string()).collect();
                    writeln!(
                        out,
                        "{log:<6} {}",
                        if list.is_empty() {
                            "(no files)".to_string()
                        } else {
                            list.join(", ")
                        }
                    )?;
                }
            }
            ".schema" => match self.catalog.schema(arg) {
                Some(s) => {
                    for c in &s.columns {
                        writeln!(out, "{:<24} {}", c.name, c.ty)?;
                    }
                    writeln!(
                        out,
                        "aliases: src=id.orig_h sport=id.orig_p dst=id.resp_h dport=id.resp_p"
                    )?;
                }
                None => {
                    writeln!(out, "unknown log `{arg}`; try .logs")?;
                    return Ok(Some(false));
                }
            },
            ".explain" => match crate::compile(arg, &self.catalog) {
                Ok(plan) => writeln!(out, "{plan}")?,
                Err(d) => {
                    writeln!(out, "{}", d.render(arg))?;
                    return Ok(Some(false));
                }
            },
            ".format" => match arg.parse::<OutputFormat>() {
                Ok(f) => self.format = f,
                Err(e) => {
                    writeln!(out, "{e}")?;
                    return Ok(Some(false));
                }
            },
            ".stats" => self.show_stats = arg != "off",
            ".functions" => {
                writeln!(out, "operators: {}", STAGE_NAMES.join(", "))?;
                writeln!(out, "aggregations: {}", AggFunc::NAMES.join(", "))?;
                for (_, _, sig) in FUNCTIONS {
                    writeln!(out, "  {sig}")?;
                }
            }
            other => {
                writeln!(out, "unknown command `{other}`; try .help")?;
                return Ok(Some(false));
            }
        }
        Ok(None)
    }
}
