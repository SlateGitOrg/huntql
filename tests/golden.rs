//! Golden tests: every `tests/golden/*.hql` query is run against the
//! committed fixtures and its output (or rendered error) is compared with the
//! sibling `.out` file. Directives in leading comments:
//!
//! * `# data: json` — run against `fixtures/json` instead of `fixtures/demo`
//! * `# explain` — compare the plan instead of the results
//!
//! Regenerate expectations with `UPDATE_GOLDEN=1 cargo test --test golden`.

use std::path::{Path, PathBuf};

use huntql::exec::ExecOptions;
use huntql::{Catalog, OutputFormat};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn render(query: &str) -> String {
    let data = if query.contains("# data: json") {
        "json"
    } else {
        "demo"
    };
    let cat = Catalog::from_dir(&root().join("fixtures").join(data)).expect("fixture dir");
    if query.contains("# explain") {
        return match huntql::compile(query, &cat) {
            Ok(plan) => format!("{plan}\n"),
            Err(d) => format!("{}\n", d.render(query)),
        };
    }
    let mut buf = Vec::new();
    let result = huntql::run_query(
        query,
        &cat,
        OutputFormat::Table,
        Box::new(&mut buf),
        ExecOptions::default(),
    );
    match result {
        Ok(_) => String::from_utf8(buf).expect("utf-8 output"),
        Err(e) => format!("{}\n", e.render(query)),
    }
}

fn check(path: &Path) -> Result<(), String> {
    let query = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let actual = render(&query);
    let out_path = path.with_extension("out");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&out_path, &actual).map_err(|e| e.to_string())?;
        return Ok(());
    }
    let expected = std::fs::read_to_string(&out_path)
        .map_err(|_| format!("missing {} (run with UPDATE_GOLDEN=1)", out_path.display()))?;
    if expected != actual {
        return Err(format!(
            "golden mismatch for {}\n--- expected\n{expected}\n--- actual\n{actual}",
            path.display()
        ));
    }
    Ok(())
}

#[test]
fn golden_queries() {
    let dir = root().join("tests/golden");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("golden dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "hql"))
        .collect();
    files.sort();
    assert!(
        files.len() >= 20,
        "expected the golden suite, found {}",
        files.len()
    );
    let failures: Vec<String> = files.iter().filter_map(|f| check(f).err()).collect();
    assert!(
        failures.is_empty(),
        "{} golden failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
