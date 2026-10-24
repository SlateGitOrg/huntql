//! Tests of the `huntql` binary: every subcommand, exit codes and stderr.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntql"))
}

fn demo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/demo")
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("binary runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn query_subcommand() {
    let d = demo();
    let o = run(&[
        "-d",
        d.to_str().unwrap(),
        "query",
        "conn | stats count() by proto",
        "--stats",
        "-f",
        "tsv",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).starts_with("proto\tcount\ntcp\t"));
    assert!(stderr(&o).contains("scanned 14785 rows"), "{}", stderr(&o));
}

#[test]
fn query_error_exit_code_and_snippet() {
    let d = demo();
    let o = run(&[
        "-d",
        d.to_str().unwrap(),
        "query",
        "conn | where duration > 30",
    ]);
    assert_eq!(o.status.code(), Some(1));
    let e = stderr(&o);
    assert!(
        e.contains("error[plan]: cannot compare duration with int"),
        "{e}"
    );
    assert!(e.contains("^^^^^^^^^^^^^"), "{e}");
}

#[test]
fn run_file_with_multiple_queries() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-run");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("q.hql");
    std::fs::write(
        &f,
        "# two hunts\nconn | stats count();\n\nssl | stack ja3 | head 1;\n",
    )
    .unwrap();
    let d = demo();
    let o = run(&["-d", d.to_str().unwrap(), "run", f.to_str().unwrap()]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.starts_with("== conn | stats count()\n"), "{out}");
    assert!(out.contains("\n== ssl | stack ja3 | head 1\n"), "{out}");
    // A planning error in the second query is reported against the file text.
    std::fs::write(&f, "conn | head 1;\nconn | where nope == 1;\n").unwrap();
    let o = run(&["-d", d.to_str().unwrap(), "run", f.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("--> 2:14"), "{}", stderr(&o));
    // A syntax error stops before running anything.
    std::fs::write(&f, "conn | head 1;\nconn | ;\n").unwrap();
    let o = run(&["-d", d.to_str().unwrap(), "run", f.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).is_empty());
    let o = run(&["run", "/definitely/missing.hql"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn repl_reads_piped_input() {
    let d = demo();
    let mut child = bin()
        .args(["-d", d.to_str().unwrap(), "repl"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b".help\n.logs\n.schema conn\n.functions\n.format tsv\n.stats on\nconn |\n  stats count()\n\n\
              .explain conn | sort -ts | head 3\n.format xml\n.schema nope\n.explain conn | where\n.bogus\n\
              conn | where nope\n.stats off\n.format json\nconn | stats count();\n.quit\nconn | head\n",
        )
        .unwrap();
    let o = child.wait_with_output().unwrap();
    let out = stdout(&o);
    assert!(out.contains("Commands:"));
    assert!(out.contains("conn   "), "{out}");
    assert!(out.contains("id.orig_h                addr"));
    assert!(out.contains("entropy(string)"));
    assert!(out.contains("count\n14785\n"), "{out}");
    assert!(out.contains("-- scanned 14785 rows"));
    assert!(out.contains("TopK k=3 [-ts]"));
    assert!(out.contains("unknown format `xml`"));
    assert!(out.contains("unknown log `nope`"));
    assert!(out.contains("expected an expression"));
    assert!(out.contains("unknown command `.bogus`"));
    assert!(out.contains("unknown field `nope`"));
    assert!(out.contains("{\"count\":14785}"));
    // Failures make a non-interactive session exit non-zero.
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn explain_and_schema() {
    let d = demo();
    let o = run(&[
        "-d",
        d.to_str().unwrap(),
        "explain",
        "conn | where dport == 443 | stats count() by src | sort -count | head 10",
    ]);
    assert!(o.status.success());
    let out = stdout(&o);
    assert!(
        out.contains("Scan conn (decode 2 of 21 columns: id.orig_h, id.resp_p)"),
        "{out}"
    );
    assert!(out.contains("TopK k=10"));
    let o = run(&["-d", d.to_str().unwrap(), "explain", "conn | sort"]);
    assert_eq!(o.status.code(), Some(1));
    let o = run(&["-d", d.to_str().unwrap(), "schema", "dns"]);
    assert!(stdout(&o).contains("  query                    string"));
    let o = run(&["-d", d.to_str().unwrap(), "schema"]);
    assert!(stdout(&o).contains("ssl:"));
    let o = run(&["-d", d.to_str().unwrap(), "schema", "nope"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn gen_is_deterministic_and_reproduces_fixture() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-gen");
    let _ = std::fs::remove_dir_all(&dir);
    let o = run(&[
        "gen",
        "--out",
        dir.to_str().unwrap(),
        "--seed",
        "7",
        "--hours",
        "12",
        "--hosts",
        "25",
        "--beacons",
        "6",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("conn.log (14785 rows)"));
    // The committed demo fixture is exactly this generator output.
    for f in ["conn.log", "dns.log", "http.log", "ssl.log", "truth.json"] {
        let a = std::fs::read(dir.join(f)).unwrap();
        let b = std::fs::read(demo().join(f)).unwrap();
        assert!(
            a == b,
            "{f} differs from fixtures/demo; regenerate with `make fixtures`"
        );
    }
    let json = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-gen-json");
    let o = run(&[
        "gen",
        "--out",
        json.to_str().unwrap(),
        "--seed",
        "11",
        "--hours",
        "3",
        "--hosts",
        "6",
        "--beacons",
        "2",
        "--log-format",
        "json",
    ]);
    assert!(o.status.success());
    let fixture_json = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/json/conn.json");
    assert_eq!(
        std::fs::read(json.join("conn.json")).unwrap(),
        std::fs::read(fixture_json).unwrap()
    );
    let o = run(&["gen", "--out", dir.to_str().unwrap(), "--hosts", "0"]);
    assert_eq!(o.status.code(), Some(2));
    let only = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-gen-only");
    let _ = std::fs::remove_dir_all(&only);
    let o = run(&[
        "gen",
        "--out",
        only.to_str().unwrap(),
        "--hours",
        "1",
        "--logs",
        "conn,dns",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(only.join("dns.log").exists() && !only.join("ssl.log").exists());
    let o = run(&["gen", "--out", only.to_str().unwrap(), "--logs", "weird"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn eval_subcommand_small() {
    let o = run(&[
        "eval",
        "--train",
        "1..=1",
        "--test",
        "2..=2",
        "--hours",
        "6",
        "--hosts",
        "8",
        "--beacons",
        "3",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("| combined (huntql default) |"));
    let o = run(&["eval", "--train", "1..=5", "--test", "3..=9"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("must not overlap"));
    let o = run(&["eval", "--train", "5..=1"]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["eval", "--train", "x"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn bad_data_dir_and_input_flag() {
    let o = run(&["-d", "/definitely/missing", "query", "conn | head"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("does not exist"));
    let d = demo();
    let o = run(&[
        "-d",
        d.to_str().unwrap(),
        "-i",
        "nolog",
        "query",
        "conn | head",
    ]);
    assert_eq!(o.status.code(), Some(2));
    let conn = d.join("conn.log");
    let empty = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-empty");
    std::fs::create_dir_all(&empty).unwrap();
    let o = run(&[
        "-d",
        empty.to_str().unwrap(),
        "-i",
        &format!("custom={}", conn.display()),
        "query",
        "custom | stats count()",
        "-f",
        "json",
        "-v",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o), "{\"count\":14785}\n");
}
