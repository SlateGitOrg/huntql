use std::io::{self, BufWriter, IsTerminal, Write};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use huntql::exec::ExecOptions;
use huntql::gen::{self, GenConfig, LogFormat};
use huntql::output::OutputFormat;
use huntql::planner::SchemaProvider;
use huntql::repl::Repl;
use huntql::{eval, parser, planner, Catalog};

#[derive(Parser)]
#[command(
    name = "huntql",
    version,
    about = "Pipe-based threat-hunting queries over Zeek logs"
)]
struct Cli {
    /// Directory containing Zeek logs (conn.log, dns.json, conn.*.log.gz, ...)
    #[arg(short, long, global = true, default_value = ".")]
    data: PathBuf,
    /// Extra input file as LOG=PATH (e.g. conn=/tmp/conn.log); repeatable
    #[arg(short, long = "input", global = true, value_name = "LOG=PATH")]
    inputs: Vec<String>,
    /// Log verbosity (-v info, -vv debug)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Fmt {
    Table,
    Tsv,
    Json,
}

impl From<Fmt> for OutputFormat {
    fn from(f: Fmt) -> Self {
        match f {
            Fmt::Table => OutputFormat::Table,
            Fmt::Tsv => OutputFormat::Tsv,
            Fmt::Json => OutputFormat::Json,
        }
    }
}

#[derive(clap::Args)]
struct RunOpts {
    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: Fmt,
    /// Print execution statistics to stderr
    #[arg(long)]
    stats: bool,
    /// Maximum groups/rows any blocking operator may hold
    #[arg(long, default_value_t = ExecOptions::default().max_groups)]
    max_groups: usize,
}

#[derive(Subcommand)]
enum Command {
    /// Run one query
    Query {
        query: String,
        #[command(flatten)]
        run: RunOpts,
    },
    /// Run a file of `;`-separated queries
    Run {
        file: PathBuf,
        #[command(flatten)]
        run: RunOpts,
    },
    /// Interactive shell (also reads queries from a pipe)
    Repl,
    /// Show the type-checked physical plan for a query
    Explain { query: String },
    /// List the columns of a log (or all logs)
    Schema { log: Option<String> },
    /// Generate synthetic Zeek logs with planted beacons
    Gen {
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, default_value_t = 7)]
        seed: u64,
        #[arg(long, default_value_t = 24.0)]
        hours: f64,
        #[arg(long, default_value_t = 40)]
        hosts: usize,
        #[arg(long, default_value_t = 8)]
        beacons: usize,
        #[arg(long, value_enum, default_value = "tsv")]
        log_format: GenFmt,
        /// Only write these logs (comma-separated), e.g. --logs conn,dns
        #[arg(long, value_delimiter = ',')]
        logs: Vec<String>,
    },
    /// Evaluate beacon scoring on generated train / held-out scenarios
    Eval {
        /// Training seeds (threshold selection), e.g. 1..=20
        #[arg(long, default_value = "1..=20", value_parser = parse_range)]
        train: RangeInclusive<u64>,
        /// Held-out seeds (reported metrics), e.g. 5001..=5050
        #[arg(long, default_value = "5001..=5050", value_parser = parse_range)]
        test: RangeInclusive<u64>,
        #[arg(long, default_value_t = 24.0)]
        hours: f64,
        #[arg(long, default_value_t = 40)]
        hosts: usize,
        #[arg(long, default_value_t = 8)]
        beacons: usize,
        #[arg(long, default_value_t = 10)]
        min_count: usize,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum GenFmt {
    Tsv,
    Json,
}

fn parse_range(s: &str) -> Result<RangeInclusive<u64>, String> {
    let (a, b) = s
        .split_once("..=")
        .ok_or_else(|| format!("expected A..=B, got `{s}`"))?;
    let a: u64 = a.trim().parse().map_err(|e| format!("{e}"))?;
    let b: u64 = b.trim().parse().map_err(|e| format!("{e}"))?;
    if a > b {
        return Err(format!("empty range {s}"));
    }
    Ok(a..=b)
}

fn catalog(cli: &Cli) -> Result<Catalog, String> {
    let mut cat = if cli.data.is_dir() {
        Catalog::from_dir(&cli.data)
            .map_err(|e| format!("cannot read {}: {e}", cli.data.display()))?
    } else {
        return Err(format!(
            "data directory {} does not exist",
            cli.data.display()
        ));
    };
    for spec in &cli.inputs {
        let (log, path) = spec
            .split_once('=')
            .ok_or_else(|| format!("--input expects LOG=PATH, got `{spec}`"))?;
        cat.add_file(log, PathBuf::from(path));
    }
    Ok(cat)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .format_timestamp(None)
        .init();
    match real_main(&cli) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(2)
        }
    }
}

fn real_main(cli: &Cli) -> Result<ExitCode, String> {
    let stdout = io::stdout();
    match &cli.command {
        Command::Query { query, run } => {
            let cat = catalog(cli)?;
            let out = Box::new(BufWriter::new(stdout.lock()));
            let opts = ExecOptions {
                max_groups: run.max_groups,
            };
            match huntql::run_query(query, &cat, run.format.into(), out, opts) {
                Ok(stats) => {
                    if run.stats {
                        eprintln!("-- {stats}");
                    }
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("{}", e.render(query));
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::Run { file, run } => {
            let cat = catalog(cli)?;
            let text = std::fs::read_to_string(file)
                .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
            let queries = match parser::parse_script(&text) {
                Ok(q) => q,
                Err(d) => {
                    eprintln!("{}", d.render(&text));
                    return Ok(ExitCode::FAILURE);
                }
            };
            let opts = ExecOptions {
                max_groups: run.max_groups,
            };
            let mut failed = false;
            for (i, q) in queries.iter().enumerate() {
                let snippet = text[q.span.start..q.span.end]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                {
                    let mut lock = stdout.lock();
                    let _ = writeln!(lock, "{}== {snippet}", if i > 0 { "\n" } else { "" });
                }
                let plan = match planner::plan(q, &cat) {
                    Ok(p) => p,
                    Err(d) => {
                        eprintln!("{}", d.render(&text));
                        failed = true;
                        continue;
                    }
                };
                let out = Box::new(BufWriter::new(stdout.lock()));
                match huntql::run_plan(&plan, &cat, run.format.into(), out, opts) {
                    Ok(stats) => {
                        if run.stats {
                            eprintln!("-- {stats}");
                        }
                    }
                    Err(e) => {
                        eprintln!("{}", e.render(&text));
                        failed = true;
                    }
                }
            }
            Ok(if failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }
        Command::Repl => {
            let cat = catalog(cli)?;
            let mut repl = Repl::new(cat);
            let stdin = io::stdin();
            let interactive = stdin.is_terminal();
            if interactive {
                println!(
                    "huntql {} — .help for commands, .quit to leave",
                    env!("CARGO_PKG_VERSION")
                );
            }
            let mut out = stdout.lock();
            let failures = repl
                .run(&mut stdin.lock(), &mut out, interactive)
                .map_err(|e| e.to_string())?;
            Ok(if failures > 0 && !interactive {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }
        Command::Explain { query } => {
            let cat = catalog(cli)?;
            match huntql::compile(query, &cat) {
                Ok(plan) => {
                    println!("{plan}");
                    Ok(ExitCode::SUCCESS)
                }
                Err(d) => {
                    eprintln!("{}", d.render(query));
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::Schema { log } => {
            let cat = catalog(cli)?;
            let logs = match log {
                Some(l) => vec![l.clone()],
                None => cat.logs(),
            };
            for l in logs {
                let Some(s) = cat.schema(&l) else {
                    return Err(format!("unknown log `{l}`"));
                };
                println!("{l}:");
                for c in &s.columns {
                    println!("  {:<24} {}", c.name, c.ty);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Gen {
            out,
            seed,
            hours,
            hosts,
            beacons,
            log_format,
            logs,
        } => {
            if *hosts == 0 || *hours <= 0.0 {
                return Err("--hosts and --hours must be positive".into());
            }
            let cfg = GenConfig {
                seed: *seed,
                hours: *hours,
                hosts: *hosts,
                beacons: (*beacons).min(250),
                ..GenConfig::default()
            };
            let mut scn = gen::generate(&cfg);
            if !logs.is_empty() {
                if let Some(bad) = logs.iter().find(|l| !scn.logs.contains_key(l.as_str())) {
                    return Err(format!(
                        "unknown log `{bad}` (expected conn, dns, http, ssl)"
                    ));
                }
                scn.logs.retain(|name, _| logs.iter().any(|l| l == name));
            }
            let fmt = match log_format {
                GenFmt::Tsv => LogFormat::Tsv,
                GenFmt::Json => LogFormat::Json,
            };
            let written =
                gen::write_scenario(&scn, out, fmt, cfg.start_us).map_err(|e| e.to_string())?;
            println!("wrote to {}: {}", out.display(), written.join(", "));
            Ok(ExitCode::SUCCESS)
        }
        Command::Eval {
            train,
            test,
            hours,
            hosts,
            beacons,
            min_count,
        } => {
            if train.end() >= test.start() && test.end() >= train.start() {
                return Err("train and test seed ranges must not overlap".into());
            }
            let cfg = eval::EvalConfig {
                train: train.clone(),
                test: test.clone(),
                gen: GenConfig {
                    hours: *hours,
                    hosts: *hosts,
                    beacons: *beacons,
                    ..GenConfig::default()
                },
                min_count: (*min_count).max(3),
            };
            print!("{}", eval::run(&cfg));
            Ok(ExitCode::SUCCESS)
        }
    }
}
