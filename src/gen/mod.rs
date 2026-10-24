//! Synthetic Zeek log generator with planted beacons.
//!
//! Produces `conn`, `dns`, `http` and `ssl` logs for a small fictional
//! network plus a `truth.json` describing what was planted. Everything is
//! deterministic for a given seed. All addresses come from ranges reserved
//! for documentation/benchmarking (10.20.0.0/16 internal, 198.18.0.0/15 for
//! benign servers, 203.0.113.0/24 for planted C2) and all names use the
//! reserved `.example` / `.test` TLDs, so generated data can never point at
//! a real third party.
//!
//! Traffic model:
//! * **Browsing** (benign, bursty): per-host Poisson session arrivals with a
//!   diurnal profile; each session makes a burst of connections to
//!   Zipf-popular sites with exponential gaps, each preceded by a DNS lookup
//!   and followed by an `ssl` or `http` record.
//! * **Pollers** (benign hard negatives): long-lived update/telemetry agents
//!   connecting to the same server as a *Poisson* process (memoryless) at
//!   beacon-like average rates with consistent payload sizes.
//! * **Sync clients** (benign hard negatives): heavy-tailed (log-normal)
//!   inter-arrival times.
//! * **Beacons** (planted positives): implant-style check-ins with period P
//!   and jitter j drawn per beacon; interval = P * (1 - j * U(0,1)) (the
//!   Cobalt-Strike-style "sleep minus up to j" convention), optional
//!   dropped check-ins and optional interleaved operator activity on the
//!   same channel.

pub mod rng;

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use serde::Serialize;

use crate::exec::Row;
use crate::schema::{self, Schema};
use crate::timefmt;
use crate::value::{Type, Value};
use rng::Rng;

/// Generator settings.
#[derive(Debug, Clone)]
pub struct GenConfig {
    pub seed: u64,
    /// Start of the capture, microseconds since the epoch.
    pub start_us: i64,
    pub hours: f64,
    pub hosts: usize,
    pub beacons: usize,
    pub pollers_per_host: f64,
}

impl Default for GenConfig {
    fn default() -> Self {
        GenConfig {
            seed: 1,
            // 2024-03-04T00:00:00Z
            start_us: 1_709_510_400_000_000,
            hours: 24.0,
            hosts: 40,
            beacons: 8,
            pollers_per_host: 1.0,
        }
    }
}

/// Parameters of one planted beacon (ground truth).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PlantedBeacon {
    pub src: String,
    pub dst: String,
    pub dport: u16,
    pub domain: String,
    pub period_s: f64,
    pub jitter: f64,
    pub dropout: f64,
    /// Extra operator connections per beacon period on the same channel.
    pub interleave: f64,
    pub first: String,
    pub connections: usize,
}

/// Kind of a benign channel deliberately generated as a hard negative.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NegativeKind {
    Poller,
    SyncClient,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HardNegative {
    pub src: String,
    pub dst: String,
    pub dport: u16,
    pub kind: NegativeKind,
    pub mean_interval_s: f64,
}

/// Ground truth written to `truth.json`.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Truth {
    pub seed: u64,
    pub beacons: Vec<PlantedBeacon>,
    pub hard_negatives: Vec<HardNegative>,
    /// Other planted hunt artifacts (rare user agent, DGA-like lookups).
    pub notes: Vec<String>,
}

/// A generated dataset: rows per log (sorted by `ts`) and the ground truth.
pub struct Scenario {
    pub logs: BTreeMap<&'static str, (Schema, Vec<Row>)>,
    pub truth: Truth,
}

const NORMAL_UAS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
];
const IMPLANT_UA: &str = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)";
const NORMAL_JA3: &[&str] = &[
    "773906b0efdefa24a7f2b8eb6985bf37",
    "cd08e31494f9531f560d64c695473da9",
    "b32309a26951912be7dba376398abc3b",
];
const IMPLANT_JA3: &str = "72a589da586844d7f0818ce684948eea";

/// Benign destinations: (name, weight rank). Popularity is Zipf by index.
fn site_names() -> Vec<String> {
    let words = [
        "news", "mail", "cdn", "search", "video", "docs", "chat", "shop", "wiki", "maps", "cloud",
        "social", "music", "weather", "sports", "bank", "travel", "code", "photos", "forum",
    ];
    let tlds = ["example", "example.com", "example.net", "example.org"];
    let mut out = Vec::new();
    for (i, w) in words.iter().enumerate() {
        for (j, t) in tlds.iter().enumerate() {
            if (i + j) % 2 == 0 {
                out.push(format!("{w}.{t}"));
            }
        }
    }
    out
}

/// Deterministic address in 198.18.0.0/15 for a benign name.
fn benign_ip(name: &str) -> IpAddr {
    let h = name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    IpAddr::V4(Ipv4Addr::new(
        198,
        18 + (h & 1) as u8,
        ((h >> 8) & 0xff) as u8,
        ((h >> 16) % 254 + 1) as u8,
    ))
}

fn uid(rng: &mut Rng) -> String {
    const ALPHA: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut s = String::from("C");
    for _ in 0..17 {
        s.push(ALPHA[rng.range(0, ALPHA.len() as u64) as usize] as char);
    }
    s
}

/// Builds a row for a log by field name.
struct RowBuilder<'a> {
    schema: &'a Schema,
    row: Row,
}

impl<'a> RowBuilder<'a> {
    fn new(schema: &'a Schema) -> Self {
        RowBuilder {
            schema,
            row: vec![Value::Null; schema.len()],
        }
    }

    fn set(mut self, field: &str, v: Value) -> Self {
        let i = self
            .schema
            .index_of(field)
            .unwrap_or_else(|| panic!("generator bug: no field {field}"));
        self.row[i] = v;
        self
    }

    fn done(self) -> Row {
        self.row
    }
}

/// One generated connection with its application-layer context.
struct Conn {
    ts: i64,
    src: IpAddr,
    dst: IpAddr,
    dport: u16,
    domain: String,
    orig_bytes: i64,
    resp_bytes: i64,
    duration: i64,
    ua: &'static str,
    ja3: &'static str,
    uri: String,
}

struct Builder {
    rng: Rng,
    schemas: BTreeMap<&'static str, Schema>,
    rows: BTreeMap<&'static str, Vec<Row>>,
    resolver: IpAddr,
    start: i64,
    end: i64,
}

impl Builder {
    fn emit_conn(&mut self, c: &Conn, with_dns: bool) {
        let sport = self.rng.range(49152, 65535) as i64;
        let id = uid(&mut self.rng);
        if with_dns {
            self.emit_dns(c.ts - 20_000, c.src, &c.domain, Some(c.dst));
        }
        let tls = c.dport != 80;
        let service = if tls { "ssl" } else { "http" };
        let orig_pkts = c.orig_bytes / 500 + 3;
        let resp_pkts = c.resp_bytes / 1200 + 3;
        let conn = RowBuilder::new(&self.schemas["conn"])
            .set("ts", Value::Time(c.ts))
            .set("uid", Value::str(&id))
            .set("id.orig_h", Value::Addr(c.src))
            .set("id.orig_p", Value::Int(sport))
            .set("id.resp_h", Value::Addr(c.dst))
            .set("id.resp_p", Value::Int(i64::from(c.dport)))
            .set("proto", Value::str("tcp"))
            .set("service", Value::str(service))
            .set("duration", Value::Duration(c.duration))
            .set("orig_bytes", Value::Int(c.orig_bytes))
            .set("resp_bytes", Value::Int(c.resp_bytes))
            .set("conn_state", Value::str("SF"))
            .set("local_orig", Value::Bool(true))
            .set("local_resp", Value::Bool(false))
            .set("missed_bytes", Value::Int(0))
            .set("history", Value::str("ShADadFf"))
            .set("orig_pkts", Value::Int(orig_pkts))
            .set("orig_ip_bytes", Value::Int(c.orig_bytes + orig_pkts * 52))
            .set("resp_pkts", Value::Int(resp_pkts))
            .set("resp_ip_bytes", Value::Int(c.resp_bytes + resp_pkts * 52))
            .done();
        self.rows.entry("conn").or_default().push(conn);
        fn base<'s>(b: RowBuilder<'s>, c: &Conn, id: &str, sport: i64) -> RowBuilder<'s> {
            b.set("ts", Value::Time(c.ts + 1_000))
                .set("uid", Value::str(id))
                .set("id.orig_h", Value::Addr(c.src))
                .set("id.orig_p", Value::Int(sport))
                .set("id.resp_h", Value::Addr(c.dst))
                .set("id.resp_p", Value::Int(i64::from(c.dport)))
        }
        if tls {
            let row = base(RowBuilder::new(&self.schemas["ssl"]), c, &id, sport)
                .set("version", Value::str("TLSv13"))
                .set("cipher", Value::str("TLS_AES_128_GCM_SHA256"))
                .set("curve", Value::str("x25519"))
                .set("server_name", Value::str(&c.domain))
                .set("resumed", Value::Bool(false))
                .set("established", Value::Bool(true))
                .set("ssl_history", Value::str("CsiI"))
                .set("ja3", Value::str(c.ja3))
                .done();
            self.rows.entry("ssl").or_default().push(row);
        } else {
            let row = base(RowBuilder::new(&self.schemas["http"]), c, &id, sport)
                .set("trans_depth", Value::Int(1))
                .set(
                    "method",
                    Value::str(if c.uri.starts_with("/submit") {
                        "POST"
                    } else {
                        "GET"
                    }),
                )
                .set("host", Value::str(&c.domain))
                .set("uri", Value::str(&c.uri))
                .set("version", Value::str("1.1"))
                .set("user_agent", Value::str(c.ua))
                .set(
                    "request_body_len",
                    Value::Int(c.orig_bytes.saturating_sub(300).max(0)),
                )
                .set(
                    "response_body_len",
                    Value::Int(c.resp_bytes.saturating_sub(250).max(0)),
                )
                .set("status_code", Value::Int(200))
                .set("status_msg", Value::str("OK"))
                .done();
            self.rows.entry("http").or_default().push(row);
        }
    }

    fn emit_dns(&mut self, ts: i64, src: IpAddr, query: &str, answer: Option<IpAddr>) {
        let id = uid(&mut self.rng);
        let (rcode, rname) = if answer.is_some() {
            (0, "NOERROR")
        } else {
            (3, "NXDOMAIN")
        };
        let row = RowBuilder::new(&self.schemas["dns"])
            .set("ts", Value::Time(ts))
            .set("uid", Value::str(&id))
            .set("id.orig_h", Value::Addr(src))
            .set("id.orig_p", Value::Int(self.rng.range(1024, 65535) as i64))
            .set("id.resp_h", Value::Addr(self.resolver))
            .set("id.resp_p", Value::Int(53))
            .set("proto", Value::str("udp"))
            .set("trans_id", Value::Int(self.rng.range(1, 65535) as i64))
            .set("rtt", Value::Duration(self.rng.range(300, 30_000) as i64))
            .set("query", Value::str(query))
            .set("qclass", Value::Int(1))
            .set("qclass_name", Value::str("C_INTERNET"))
            .set("qtype", Value::Int(1))
            .set("qtype_name", Value::str("A"))
            .set("rcode", Value::Int(rcode))
            .set("rcode_name", Value::str(rname))
            .set("AA", Value::Bool(false))
            .set("TC", Value::Bool(false))
            .set("RD", Value::Bool(true))
            .set("RA", Value::Bool(true))
            .set("Z", Value::Int(0))
            .set(
                "answers",
                answer.map_or(Value::Null, |a| Value::str(&a.to_string())),
            )
            .set(
                "TTLs",
                answer.map_or(Value::Null, |_| Value::str("300.000000")),
            )
            .set("rejected", Value::Bool(false))
            .done();
        self.rows.entry("dns").or_default().push(row);
    }

    fn in_range(&self, t: i64) -> bool {
        t >= self.start && t < self.end
    }
}

/// Diurnal activity multiplier for UTC hour `h` (peaks during work hours).
fn diurnal(h: i64) -> f64 {
    match h {
        8..=17 => 1.6,
        6 | 7 | 18..=21 => 0.9,
        _ => 0.25,
    }
}

const PERIODS: &[f64] = &[30.0, 60.0, 120.0, 300.0, 600.0, 900.0, 1800.0, 3600.0];
const JITTERS: &[f64] = &[0.0, 0.1, 0.2, 0.3, 0.5, 0.8];

/// Generate a scenario.
pub fn generate(cfg: &GenConfig) -> Scenario {
    let mut root = Rng::new(cfg.seed);
    let start = cfg.start_us;
    let end = start + (cfg.hours * 3600.0 * 1e6) as i64;
    let schemas: BTreeMap<&'static str, Schema> = schema::LOG_NAMES
        .iter()
        .map(|l| (*l, schema::builtin(l).expect("builtin")))
        .collect();
    let mut b = Builder {
        rng: root.fork(1),
        schemas,
        rows: BTreeMap::new(),
        resolver: IpAddr::V4(Ipv4Addr::new(10, 20, 0, 53)),
        start,
        end,
    };
    let hosts: Vec<IpAddr> = (0..cfg.hosts)
        .map(|i| {
            IpAddr::V4(Ipv4Addr::new(
                10,
                20,
                1 + (i / 200) as u8,
                10 + (i % 200) as u8,
            ))
        })
        .collect();
    let host_ua: Vec<&'static str> = (0..cfg.hosts)
        .map(|i| NORMAL_UAS[i % NORMAL_UAS.len()])
        .collect();
    let host_ja3: Vec<&'static str> = (0..cfg.hosts)
        .map(|i| NORMAL_JA3[i % NORMAL_JA3.len()])
        .collect();
    let sites = site_names();
    let mut truth = Truth {
        seed: cfg.seed,
        ..Truth::default()
    };

    // --- Browsing --------------------------------------------------------
    for (h, &src) in hosts.iter().enumerate() {
        let mut rng = root.fork(100 + h as u64);
        let rate_per_hour = 0.5 + rng.next_f64() * 3.0;
        let mut t = start;
        loop {
            // Thinning for the diurnal profile (max multiplier 1.6).
            t += (rng.exp(3600.0 / (rate_per_hour * 1.6)) * 1e6) as i64;
            if t >= end {
                break;
            }
            let hour = (t / 1_000_000 / 3600).rem_euclid(24);
            if !rng.chance(diurnal(hour) / 1.6) {
                continue;
            }
            let burst = 3 + rng.exp(8.0) as usize;
            let mut ct = t;
            let mut looked_up: Vec<usize> = Vec::new();
            for _ in 0..burst {
                ct += (rng.exp(6.0) * 1e6) as i64 + 1;
                if ct >= end {
                    break;
                }
                let site = rng.zipf(sites.len());
                let first = !looked_up.contains(&site);
                looked_up.push(site);
                let domain = sites[site].clone();
                let dport = if rng.chance(0.85) { 443 } else { 80 };
                let c = Conn {
                    ts: ct,
                    src,
                    dst: benign_ip(&domain),
                    dport,
                    orig_bytes: (rng.exp(900.0) as i64) + 200,
                    resp_bytes: (rng.exp(40_000.0) as i64) + 500,
                    duration: (rng.exp(2.0) * 1e6) as i64 + 1000,
                    ua: host_ua[h],
                    ja3: host_ja3[h],
                    uri: format!(
                        "/{}",
                        [
                            "",
                            "index.html",
                            "api/v1/feed",
                            "static/app.js",
                            "img/logo.png"
                        ][rng.range(0, 5) as usize]
                    ),
                    domain,
                };
                b.emit_conn(&c, first);
            }
        }
    }

    // --- Pollers and sync clients (hard negatives) --------------------------
    for (h, &src) in hosts.iter().enumerate() {
        let mut rng = root.fork(10_000 + h as u64);
        let n = (cfg.pollers_per_host + rng.next_f64() * 0.999).floor() as usize;
        for p in 0..n {
            let sync = rng.chance(0.3);
            let domain = if sync {
                format!("sync{}.example.net", rng.range(1, 30))
            } else {
                format!("updates{}.example.com", rng.range(1, 30))
            };
            let dst = benign_ip(&domain);
            let mean = *rng.pick(PERIODS);
            let size = 300 + rng.range(0, 2000) as i64;
            let mut t = start + (rng.next_f64() * mean * 1e6) as i64;
            let mut emitted = 0;
            while t < end {
                let c = Conn {
                    ts: t,
                    src,
                    dst,
                    dport: 443,
                    domain: domain.clone(),
                    orig_bytes: size + rng.range(0, 40) as i64,
                    resp_bytes: 800 + rng.range(0, 400) as i64,
                    duration: (rng.exp(0.5) * 1e6) as i64 + 1000,
                    ua: host_ua[h],
                    ja3: host_ja3[h],
                    uri: "/".into(),
                };
                b.emit_conn(&c, emitted == 0 || rng.chance(0.05));
                emitted += 1;
                let gap = if sync {
                    // Log-normal with the same mean: heavy tail, bursty.
                    let sigma: f64 = 1.2;
                    let mu = mean.ln() - sigma * sigma / 2.0;
                    (mu + sigma * rng.normal()).exp()
                } else {
                    rng.exp(mean)
                };
                t += (gap * 1e6) as i64 + 1;
            }
            let _ = p;
            truth.hard_negatives.push(HardNegative {
                src: src.to_string(),
                dst: dst.to_string(),
                dport: 443,
                kind: if sync {
                    NegativeKind::SyncClient
                } else {
                    NegativeKind::Poller
                },
                mean_interval_s: mean,
            });
        }
    }

    // --- Beacons (positives) -----------------------------------------------
    let mut used_dst = std::collections::HashSet::new();
    for i in 0..cfg.beacons {
        let mut rng = root.fork(50_000 + i as u64);
        let h = rng.range(0, hosts.len() as u64) as usize;
        let src = hosts[h];
        let mut octet = rng.range(1, 255) as u8;
        while !used_dst.insert(octet) {
            octet = octet % 254 + 1;
        }
        let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, octet));
        let label: String = (0..8)
            .map(|_| (b'a' + rng.range(0, 26) as u8) as char)
            .collect();
        let domain = format!("{label}.test");
        let period = *rng.pick(PERIODS);
        let jitter = *rng.pick(JITTERS);
        let dropout = *rng.pick(&[0.0, 0.0, 0.1, 0.25]);
        let interleave = if rng.chance(0.3) {
            *rng.pick(&[0.5, 1.0])
        } else {
            0.0
        };
        let dport = *rng.pick(&[443u16, 443, 8443, 80]);
        let span = (end - start) as f64;
        let first = start + (rng.next_f64() * 0.25 * span) as i64;
        let size = 180 + rng.range(0, 400) as i64;
        let mut t = first;
        let mut n = 0usize;
        let mut k = 0usize;
        while b.in_range(t) {
            if !rng.chance(dropout) {
                // Occasional tasking makes some check-ins larger.
                let tasked = rng.chance(0.05);
                let c = Conn {
                    ts: t,
                    src,
                    dst,
                    dport,
                    domain: domain.clone(),
                    orig_bytes: if tasked {
                        size + rng.range(1_000, 50_000) as i64
                    } else {
                        size + rng.range(0, 8) as i64
                    },
                    resp_bytes: 120 + rng.range(0, 16) as i64,
                    duration: (rng.exp(0.3) * 1e6) as i64 + 1000,
                    ua: IMPLANT_UA,
                    ja3: IMPLANT_JA3,
                    uri: format!("/submit.php?id={}", 10_000 + i),
                };
                b.emit_conn(&c, k % 12 == 0);
                n += 1;
                k += 1;
            }
            let interval = period * (1.0 - jitter * rng.next_f64());
            // Interleaved operator activity: Poisson extras within this interval.
            if interleave > 0.0 {
                let mut et = t;
                loop {
                    et += (rng.exp(period / interleave) * 1e6) as i64 + 1;
                    if et >= t + (interval * 1e6) as i64 || !b.in_range(et) {
                        break;
                    }
                    let c = Conn {
                        ts: et,
                        src,
                        dst,
                        dport,
                        domain: domain.clone(),
                        orig_bytes: 400 + rng.range(0, 20_000) as i64,
                        resp_bytes: 2_000 + rng.range(0, 200_000) as i64,
                        duration: (rng.exp(4.0) * 1e6) as i64 + 1000,
                        ua: IMPLANT_UA,
                        ja3: IMPLANT_JA3,
                        uri: format!("/submit.php?id={}", 10_000 + i),
                    };
                    b.emit_conn(&c, false);
                    n += 1;
                }
            }
            t += (interval * 1e6) as i64;
        }
        truth.beacons.push(PlantedBeacon {
            src: src.to_string(),
            dst: dst.to_string(),
            dport,
            domain,
            period_s: period,
            jitter,
            dropout,
            interleave,
            first: timefmt::format_iso(first),
            connections: n,
        });
    }

    // --- DGA-like lookups from one host (for entropy / rare hunts) ----------
    let mut rng = root.fork(90_000);
    let dga_host = hosts[rng.range(0, hosts.len() as u64) as usize];
    let dga_start = start + ((end - start) as f64 * 0.6) as i64;
    for j in 0..30 {
        let len = 12 + rng.range(0, 8) as usize;
        let name: String = (0..len)
            .map(|_| {
                let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
                alphabet[rng.range(0, alphabet.len() as u64) as usize] as char
            })
            .collect();
        let ts = dga_start + j * 7_000_000 + rng.range(0, 1_000_000) as i64;
        if ts < end {
            b.emit_dns(ts, dga_host, &format!("{name}.test"), None);
        }
    }
    truth.notes.push(format!(
        "{dga_host} issues ~30 NXDOMAIN lookups for random-looking .test names starting at {}",
        timefmt::format_iso(dga_start)
    ));
    truth.notes.push(format!(
        "beacons use user agent {IMPLANT_UA:?} (http) and JA3 {IMPLANT_JA3} (ssl)"
    ));

    let schemas = b.schemas;
    let mut rows = b.rows;
    let mut logs = BTreeMap::new();
    for (name, schema) in schemas {
        let mut r = rows.remove(name).unwrap_or_default();
        let ts = schema.index_of("ts").expect("ts");
        r.sort_by(|a, c| a[ts].total_cmp(&c[ts]));
        logs.insert(name, (schema, r));
    }
    Scenario { logs, truth }
}

/// Encode a value the way Zeek's ASCII writer does.
pub fn zeek_text(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::Bool(b) => (if *b { "T" } else { "F" }).into(),
        Value::Time(us) => timefmt::format_epoch(*us),
        Value::Duration(us) => timefmt::format_epoch(*us),
        Value::Str(s) if s.is_empty() => "(empty)".into(),
        Value::Str(s) => s
            .replace('\\', "\\x5c")
            .replace('\t', "\\x09")
            .replace('\n', "\\x0a"),
        other => other.to_string(),
    }
}

/// Output format for written logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Tsv,
    Json,
}

/// Write one log in Zeek TSV format.
pub fn write_tsv(
    w: &mut dyn Write,
    log: &str,
    schema: &Schema,
    rows: &[Row],
    open_ts: i64,
) -> io::Result<()> {
    let zeek = schema::zeek_fields(log);
    let names: Vec<&str> = schema.columns.iter().map(|c| c.name.as_str()).collect();
    let types: Vec<String> = match &zeek {
        Some(z) => z.iter().map(|(_, t)| t.to_string()).collect(),
        None => schema
            .columns
            .iter()
            .map(|c| zeek_type(c.ty).to_string())
            .collect(),
    };
    let stamp = |us: i64| {
        let iso = timefmt::format_iso(us.div_euclid(1_000_000) * 1_000_000);
        // 2024-03-04T00:00:00Z -> 2024-03-04-00-00-00
        iso.trim_end_matches('Z').replace(['T', ':'], "-")
    };
    writeln!(w, "#separator \\x09")?;
    writeln!(w, "#set_separator\t,")?;
    writeln!(w, "#empty_field\t(empty)")?;
    writeln!(w, "#unset_field\t-")?;
    writeln!(w, "#path\t{log}")?;
    writeln!(w, "#open\t{}", stamp(open_ts))?;
    writeln!(w, "#fields\t{}", names.join("\t"))?;
    writeln!(w, "#types\t{}", types.join("\t"))?;
    for row in rows {
        let line: Vec<String> = row.iter().map(zeek_text).collect();
        writeln!(w, "{}", line.join("\t"))?;
    }
    let last = rows
        .last()
        .and_then(|r| match r.first() {
            Some(Value::Time(t)) => Some(*t),
            _ => None,
        })
        .unwrap_or(open_ts);
    writeln!(w, "#close\t{}", stamp(last))
}

fn zeek_type(t: Type) -> &'static str {
    match t {
        Type::Bool => "bool",
        Type::Int => "count",
        Type::Float => "double",
        Type::Time => "time",
        Type::Duration => "interval",
        Type::Addr => "addr",
        Type::Subnet => "subnet",
        Type::Str | Type::Null => "string",
    }
}

/// Write one log as Zeek-style NDJSON (epoch timestamps, null fields omitted).
pub fn write_json(w: &mut dyn Write, schema: &Schema, rows: &[Row]) -> io::Result<()> {
    for row in rows {
        let mut parts = Vec::new();
        for (c, v) in schema.columns.iter().zip(row) {
            let text = match v {
                Value::Null => continue,
                Value::Time(us) | Value::Duration(us) => timefmt::format_epoch(*us),
                Value::Int(i) => i.to_string(),
                Value::Float(f) => f.to_string(),
                Value::Bool(b) => b.to_string(),
                other => serde_json::to_string(&other.to_string()).map_err(io::Error::other)?,
            };
            parts.push(format!(
                "{}:{text}",
                serde_json::to_string(&c.name).map_err(io::Error::other)?
            ));
        }
        writeln!(w, "{{{}}}", parts.join(","))?;
    }
    Ok(())
}

/// Write every log plus `truth.json` into `dir`.
pub fn write_scenario(
    scn: &Scenario,
    dir: &Path,
    format: LogFormat,
    start_us: i64,
) -> io::Result<Vec<String>> {
    std::fs::create_dir_all(dir)?;
    let mut written = Vec::new();
    for (log, (schema, rows)) in &scn.logs {
        let name = match format {
            LogFormat::Tsv => format!("{log}.log"),
            LogFormat::Json => format!("{log}.json"),
        };
        let mut f = io::BufWriter::new(std::fs::File::create(dir.join(&name))?);
        match format {
            LogFormat::Tsv => write_tsv(&mut f, log, schema, rows, start_us)?,
            LogFormat::Json => write_json(&mut f, schema, rows)?,
        }
        f.flush()?;
        written.push(format!("{name} ({} rows)", rows.len()));
    }
    let truth = serde_json::to_string_pretty(&scn.truth).map_err(io::Error::other)?;
    std::fs::write(dir.join("truth.json"), truth + "\n")?;
    written.push("truth.json".into());
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> GenConfig {
        GenConfig {
            seed: 3,
            hours: 4.0,
            hosts: 6,
            beacons: 3,
            ..GenConfig::default()
        }
    }

    #[test]
    fn deterministic_and_sorted() {
        let a = generate(&small());
        let b = generate(&small());
        assert_eq!(a.truth.beacons, b.truth.beacons);
        for (log, (_, rows)) in &a.logs {
            assert_eq!(rows.len(), b.logs[log].1.len());
            assert!(
                rows.windows(2).all(|w| w[0][0].total_cmp(&w[1][0]).is_le()),
                "{log} sorted"
            );
        }
        assert_eq!(a.truth.beacons.len(), 3);
        assert!(a
            .truth
            .beacons
            .iter()
            .all(|p| p.dst.starts_with("203.0.113.")));
        assert!(a.logs["conn"].1.len() > 100);
    }

    #[test]
    fn zeek_encoding() {
        assert_eq!(zeek_text(&Value::Null), "-");
        assert_eq!(zeek_text(&Value::str("")), "(empty)");
        assert_eq!(zeek_text(&Value::str("a\tb\\")), "a\\x09b\\x5c");
        assert_eq!(zeek_text(&Value::Bool(false)), "F");
        assert_eq!(zeek_text(&Value::Duration(1_500_000)), "1.500000");
        assert_eq!(zeek_type(Type::Float), "double");
        assert_eq!(zeek_type(Type::Subnet), "subnet");
    }

    #[test]
    fn writers_produce_parseable_output() {
        let scn = generate(&small());
        let (schema, rows) = &scn.logs["conn"];
        let mut tsv = Vec::new();
        write_tsv(&mut tsv, "conn", schema, &rows[..5], 0).unwrap();
        let text = String::from_utf8(tsv).unwrap();
        assert!(text.starts_with("#separator \\x09\n"));
        assert!(text.contains("#types\ttime\tstring\taddr\tport"));
        assert!(text
            .trim_end()
            .lines()
            .last()
            .unwrap()
            .starts_with("#close"));
        let mut js = Vec::new();
        write_json(&mut js, schema, &rows[..2]).unwrap();
        let first: serde_json::Value =
            serde_json::from_str(String::from_utf8(js).unwrap().lines().next().unwrap()).unwrap();
        assert!(first["ts"].is_number());
        assert!(first["id.orig_h"].is_string());
        let mut custom = Schema::default();
        custom.push("ts", Type::Time);
        custom.push("score", Type::Float);
        let mut out = Vec::new();
        write_tsv(&mut out, "custom", &custom, &[], 0).unwrap();
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("#types\ttime\tdouble"));
    }
}
