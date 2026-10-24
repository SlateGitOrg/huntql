//! End-to-end library tests over the committed fixtures and generated data.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use huntql::exec::{execute, CollectSink, ExecOptions, Row, VecSource};
use huntql::gen::{generate, GenConfig};
use huntql::value::Value;
use huntql::{compile, eval, BuiltinSchemas, Catalog, Error, OutputFormat};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run a query against a directory and collect the rows.
fn rows(dir: &Path, query: &str) -> Vec<Row> {
    let cat = Catalog::from_dir(dir).unwrap();
    let plan = compile(query, &cat).unwrap_or_else(|d| panic!("{}", d.render(query)));
    let mut src = cat.open_source(&plan.source).unwrap();
    let mut sink = CollectSink::default();
    execute(&plan, &mut src, &mut sink, ExecOptions::default()).unwrap();
    sink.rows
}

fn text(dir: &Path, query: &str, format: OutputFormat) -> String {
    let cat = Catalog::from_dir(dir).unwrap();
    let mut buf = Vec::new();
    huntql::run_query(
        query,
        &cat,
        format,
        Box::new(&mut buf),
        ExecOptions::default(),
    )
    .unwrap();
    String::from_utf8(buf).unwrap()
}

#[test]
fn canonical_query_runs_on_fixture() {
    let out = rows(
        &fixture("demo"),
        "conn | where dport==443 | stats count() by src | sort -count | head 10",
    );
    assert_eq!(out.len(), 10);
    let counts: Vec<i64> = out
        .iter()
        .map(|r| match r[1] {
            Value::Int(c) => c,
            _ => panic!("count must be int"),
        })
        .collect();
    assert!(
        counts.windows(2).all(|w| w[0] >= w[1]),
        "sorted descending: {counts:?}"
    );
}

#[test]
fn beacon_operator_finds_planted_beacons_in_fixture() {
    let truth: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture("demo/truth.json")).unwrap())
            .unwrap();
    let planted: HashSet<(String, String)> = truth["beacons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            (
                b["src"].as_str().unwrap().to_string(),
                b["dst"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let out = rows(&fixture("demo"), "conn | beacon");
    assert!(!out.is_empty());
    // Every alert at the default threshold is a planted beacon.
    for r in &out {
        let key = (r[0].to_string(), r[1].to_string());
        assert!(planted.contains(&key), "unexpected alert {key:?}");
    }
    // Scores are sorted descending.
    let scores: Vec<f64> = out.iter().map(|r| r[7].as_f64().unwrap()).collect();
    assert!(scores.windows(2).all(|w| w[0] >= w[1]));
}

#[test]
fn operator_scores_match_evaluation_library() {
    // The eval harness scores channels with beacon::score_series directly;
    // the operator must produce identical scores for the same rows.
    let cfg = eval::EvalConfig {
        gen: GenConfig {
            hours: 8.0,
            hosts: 10,
            beacons: 4,
            ..GenConfig::default()
        },
        ..eval::EvalConfig::default()
    };
    let lib = eval::score_scenario(42, &cfg);
    let scn = generate(&GenConfig {
        seed: 42,
        ..cfg.gen.clone()
    });
    let (_, conn_rows) = &scn.logs["conn"];
    let plan = compile("conn | beacon min_score=0 min_count=10", &BuiltinSchemas).unwrap();
    let mut sink = CollectSink::default();
    execute(
        &plan,
        &mut VecSource::new(conn_rows.clone()),
        &mut sink,
        ExecOptions::default(),
    )
    .unwrap();
    assert_eq!(sink.rows.len(), lib.candidates.len());
    for c in &lib.candidates {
        let row = sink
            .rows
            .iter()
            .find(|r| {
                r[0].to_string() == c.key.0
                    && r[1].to_string() == c.key.1
                    && r[2] == Value::Int(c.key.2)
            })
            .expect("channel present");
        let got = row[7].as_f64().unwrap();
        assert!(
            (got - c.score.score).abs() < 1e-4,
            "{got} vs {}",
            c.score.score
        );
    }
}

#[test]
fn hunting_operators_surface_planted_artifacts() {
    let demo = fixture("demo");
    // Rare user agent: the implant UA is used by exactly one host.
    let rare = rows(&demo, "http | rare user_agent by src limit=1");
    assert_eq!(rare.len(), 1);
    assert!(rare[0][0].to_string().contains("MSIE 7.0"));
    assert_eq!(rare[0][2], Value::Int(1));
    // Stack: the implant JA3 is the long tail.
    let stack = rows(&demo, "ssl | stack ja3");
    assert_eq!(stack[0][0], Value::str("72a589da586844d7f0818ce684948eea"));
    let last = stack.last().unwrap();
    assert_eq!(last[3], Value::Float(100.0));
    // first_seen: the DGA-like host resolves many never-before-seen names.
    let new = rows(
        &demo,
        "dns | first_seen src, query baseline=6h | stats count() as new_names by src | sort -new_names | head 1",
    );
    let truth = std::fs::read_to_string(demo.join("truth.json")).unwrap();
    let host = new[0][0].to_string();
    assert!(
        truth.contains(&format!("{host} issues")),
        "{host} should be the DGA host"
    );
}

#[test]
fn json_and_tsv_inputs_agree() {
    let scn = generate(&GenConfig {
        seed: 5,
        hours: 2.0,
        hosts: 4,
        beacons: 1,
        ..GenConfig::default()
    });
    let tsv = scratch("agree-tsv");
    let json = scratch("agree-json");
    huntql::gen::write_scenario(&scn, &tsv, huntql::gen::LogFormat::Tsv, 0).unwrap();
    huntql::gen::write_scenario(&scn, &json, huntql::gen::LogFormat::Json, 0).unwrap();
    for q in [
        "conn | stats count(), sum(orig_bytes), avg(duration), min(ts), max(ts) by proto",
        "dns | stack qtype_name, rcode_name",
        "ssl | stats dc(server_name) as names by src | sort src",
        "http | fields ts, src, uri, user_agent | sort ts | head 5",
    ] {
        assert_eq!(rows(&tsv, q), rows(&json, q), "{q}");
    }
}

#[test]
fn gzip_and_rotated_files_are_concatenated() {
    let dir = scratch("gz");
    let plain = std::fs::read(fixture("demo/conn.log")).unwrap();
    let text = String::from_utf8(plain).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let header: Vec<&str> = lines
        .iter()
        .take_while(|l| l.starts_with('#'))
        .copied()
        .collect();
    let data: Vec<&str> = lines
        .iter()
        .filter(|l| !l.starts_with('#'))
        .copied()
        .collect();
    let (a, b) = data.split_at(data.len() / 2);
    std::fs::write(
        dir.join("conn.00:00:00-06:00:00.log"),
        format!("{}\n{}\n", header.join("\n"), a.join("\n")),
    )
    .unwrap();
    let gz = std::fs::File::create(dir.join("conn.06:00:00-12:00:00.log.gz")).unwrap();
    let mut enc = flate2::write::GzEncoder::new(gz, flate2::Compression::fast());
    write!(enc, "{}\n{}\n", header.join("\n"), b.join("\n")).unwrap();
    enc.finish().unwrap();
    let split = rows(&dir, "conn | stats count(), dc(uid)");
    let whole = rows(&fixture("demo"), "conn | stats count(), dc(uid)");
    assert_eq!(split, whole);
}

#[test]
fn extra_columns_from_headers_are_queryable() {
    let dir = scratch("extra");
    std::fs::write(
        dir.join("conn.log"),
        "#separator \\x09\n#fields\tts\tid.orig_h\tid.resp_p\tcommunity_id\n#types\ttime\taddr\tport\tstring\n\
         1700000000.0\t10.0.0.1\t443\t1:abc\n1700000001.0\t10.0.0.2\t80\t1:def\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("notice.json"),
        "{\"ts\":1700000000.5,\"note\":\"Scan::Port_Scan\",\"n\":3}\n",
    )
    .unwrap();
    let out = rows(
        &dir,
        "conn | where community_id == \"1:def\" | fields src, dport",
    );
    assert_eq!(
        out,
        vec![vec![
            Value::Addr("10.0.0.2".parse().unwrap()),
            Value::Int(80)
        ]]
    );
    // A log type huntql has no built-in schema for, discovered from JSON keys.
    let out = rows(&dir, "notice | where n > 1 | fields note, ts");
    assert_eq!(out[0][0], Value::str("Scan::Port_Scan"));
    assert_eq!(out[0][1], Value::Time(1_700_000_000_500_000));
}

#[test]
fn group_limit_is_enforced() {
    let cat = Catalog::from_dir(&fixture("demo")).unwrap();
    let mut buf = Vec::new();
    let err = huntql::run_query(
        "conn | stats count() by uid",
        &cat,
        OutputFormat::Tsv,
        Box::new(&mut buf),
        ExecOptions { max_groups: 100 },
    )
    .unwrap_err();
    assert!(matches!(err, Error::Exec(_)));
    assert!(
        err.to_string().contains("group limit of 100 exceeded"),
        "{err}"
    );
    assert!(err.render("").starts_with("error: stats"));
}

#[test]
fn group_limit_covers_top_k_and_tail() {
    // `sort | head k` is fused into TopK and `tail n` buffers n rows; a huge
    // k or n must not lift the --max-groups cap that a plain `sort` honours.
    let cat = Catalog::from_dir(&fixture("demo")).unwrap();
    let run = |q: &str, max_groups: usize| {
        let mut buf = Vec::new();
        huntql::run_query(
            q,
            &cat,
            OutputFormat::Tsv,
            Box::new(&mut buf),
            ExecOptions { max_groups },
        )
        .map(|_| String::from_utf8(buf).unwrap())
    };
    for (q, op) in [
        ("conn | sort ts", "sort"),
        ("conn | sort ts | head 99999999999", "sort"),
        ("conn | sort -ts | head 6", "sort"),
        ("conn | tail 100000", "tail"),
        ("conn | tail 6", "tail"),
    ] {
        let err = run(q, 5).unwrap_err();
        assert!(matches!(err, Error::Exec(_)), "{q}: {err}");
        assert!(
            err.to_string().contains("group limit of 5 exceeded"),
            "{q}: {err}"
        );
        assert!(err.render("").starts_with(&format!("error: {op}")), "{q}");
    }
    // At or under the cap both operators still work and keep only k / n rows.
    for q in ["conn | sort ts | head 5", "conn | tail 5"] {
        let out = run(q, 5).unwrap_or_else(|e| panic!("{q}: {e}"));
        assert_eq!(out.lines().count(), 6, "{q}: header + 5 rows\n{out}");
    }
}

#[test]
fn missing_logs_and_query_errors_render() {
    let dir = scratch("empty");
    let cat = Catalog::from_dir(&dir).unwrap();
    let mut buf = Vec::new();
    let err = huntql::run_query(
        "conn | head",
        &cat,
        OutputFormat::Tsv,
        Box::new(&mut buf),
        ExecOptions::default(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("no `conn` logs found"), "{err}");
    let q = "conn | where dprt == 1";
    let err = huntql::run_query(
        q,
        &cat,
        OutputFormat::Tsv,
        Box::new(&mut buf),
        ExecOptions::default(),
    )
    .unwrap_err();
    assert!(err.render(q).contains("did you mean `dport`?"));
}

#[test]
fn output_formats() {
    let demo = fixture("demo");
    let q = "conn | stats count() as n by proto";
    let t = text(&demo, q, OutputFormat::Table);
    assert!(t.starts_with("proto  n\n-----  "), "{t}");
    let tsv = text(&demo, q, OutputFormat::Tsv);
    assert!(tsv.starts_with("proto\tn\ntcp\t"), "{tsv}");
    let js = text(&demo, q, OutputFormat::Json);
    let v: serde_json::Value = serde_json::from_str(js.lines().next().unwrap()).unwrap();
    assert_eq!(v["proto"], "tcp");
}
