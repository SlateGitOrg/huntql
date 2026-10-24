//! Timestamp and duration parsing/formatting without external dependencies.
//!
//! All times are microseconds since the Unix epoch (UTC); all durations are
//! microseconds. Decimal seconds are parsed digit-by-digit so that Zeek's
//! six-decimal timestamps round-trip exactly.

const US_PER_SEC: i64 = 1_000_000;

/// Parse decimal seconds (`"1700000000.123456"`, `"-0.5"`) into microseconds
/// without going through floating point. Extra fractional digits are truncated.
pub fn parse_seconds_to_micros(s: &str) -> Option<i64> {
    let (neg, body) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    if body.is_empty() {
        return None;
    }
    let (int_part, frac_part) = body.split_once('.').unwrap_or((body, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return None;
    }
    if !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole: i64 = if int_part.is_empty() {
        0
    } else {
        int_part.parse().ok()?
    };
    let mut frac: i64 = 0;
    for (i, b) in frac_part.bytes().take(6).enumerate() {
        frac += i64::from(b - b'0') * 10_i64.pow(5 - i as u32);
    }
    let v = whole.checked_mul(US_PER_SEC)?.checked_add(frac)?;
    Some(if neg { -v } else { v })
}

/// Parse either Zeek epoch seconds or an ISO-8601 UTC timestamp
/// (`2023-11-14T22:13:20.5Z`, as written by Zeek's `JSON::TS_ISO8601`).
pub fn parse_epoch_or_iso(s: &str) -> Option<i64> {
    if s.len() >= 10 && s.as_bytes().get(4) == Some(&b'-') {
        parse_iso(s)
    } else {
        parse_seconds_to_micros(s)
    }
}

/// Parse `YYYY-MM-DD[THH:MM:SS[.ffffff]][Z|+00:00]`. Only UTC offsets of zero
/// and explicit `±HH:MM` offsets are supported.
pub fn parse_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let part = s.get(from..from + len)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (year, month, day) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut micros = days_from_civil(year, month as u32, day as u32) * 86_400 * US_PER_SEC;
    if b.len() == 10 {
        return Some(micros);
    }
    if !(b[10] == b'T' || b[10] == b' ') || b.len() < 19 || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (h, m, sec) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if h > 23 || m > 59 || sec > 60 {
        return None;
    }
    micros += (h * 3600 + m * 60 + sec) * US_PER_SEC;
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        micros += parse_seconds_to_micros(&format!("0.{}", &frac[..digits]))?;
        rest = &frac[digits..];
    }
    match rest {
        "" | "Z" | "z" => Some(micros),
        off if off.len() == 6 && (off.starts_with('+') || off.starts_with('-')) => {
            let oh: i64 = off.get(1..3)?.parse().ok()?;
            let om: i64 = off.get(4..6)?.parse().ok()?;
            let delta = (oh * 3600 + om * 60) * US_PER_SEC;
            Some(if off.starts_with('+') {
                micros - delta
            } else {
                micros + delta
            })
        }
        _ => None,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format microseconds since the epoch as ISO-8601 UTC. Fractional seconds are
/// printed only when non-zero.
pub fn format_iso(us: i64) -> String {
    let secs = us.div_euclid(US_PER_SEC);
    let frac = us.rem_euclid(US_PER_SEC);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let base = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    );
    if frac == 0 {
        format!("{base}Z")
    } else {
        format!("{base}.{frac:06}Z")
    }
}

/// Format microseconds as decimal epoch seconds, as Zeek writes them.
pub fn format_epoch(us: i64) -> String {
    let sign = if us < 0 { "-" } else { "" };
    let a = us.unsigned_abs();
    format!("{sign}{}.{:06}", a / 1_000_000, a % 1_000_000)
}

/// Human-readable duration: `1h2m3s`, `250ms`, `1.5s`, `0s`.
pub fn format_duration(us: i64) -> String {
    if us == 0 {
        return "0s".into();
    }
    let sign = if us < 0 { "-" } else { "" };
    let a = us.unsigned_abs();
    if a < 1_000 {
        return format!("{sign}{a}us");
    }
    if a < 1_000_000 {
        let ms = a as f64 / 1_000.0;
        return format!("{sign}{}ms", trim_float(ms));
    }
    let total_s = a / 1_000_000;
    let frac_us = a % 1_000_000;
    let (d, h, m, s) = (
        total_s / 86_400,
        (total_s % 86_400) / 3600,
        (total_s % 3600) / 60,
        total_s % 60,
    );
    let mut out = String::from(sign);
    if d > 0 {
        out.push_str(&format!("{d}d"));
    }
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if m > 0 {
        out.push_str(&format!("{m}m"));
    }
    if s > 0 || (frac_us > 0 && total_s < 60) {
        if frac_us > 0 && total_s < 60 {
            let sec = s as f64 + frac_us as f64 / 1e6;
            out.push_str(&format!("{}s", trim_float(sec)));
        } else {
            out.push_str(&format!("{s}s"));
        }
    }
    out
}

fn trim_float(x: f64) -> String {
    let s = format!("{x:.3}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    s.to_string()
}

/// Parse a duration literal from a query: `250ms`, `30s`, `1.5m`, `2h`, `7d`,
/// `100us`. Returns microseconds.
pub fn parse_duration_literal(s: &str) -> Option<i64> {
    let split = s.find(|c: char| c.is_ascii_alphabetic())?;
    let (num, unit) = s.split_at(split);
    let mult: i64 = match unit {
        "us" => 1,
        "ms" => 1_000,
        "s" => US_PER_SEC,
        "m" => 60 * US_PER_SEC,
        "h" => 3_600 * US_PER_SEC,
        "d" => 86_400 * US_PER_SEC,
        _ => return None,
    };
    // Reuse the exact decimal parser: value * mult where value has up to 6 decimals.
    let as_micros = parse_seconds_to_micros(num)?; // num * 1e6
    let v = (i128::from(as_micros) * i128::from(mult)) / 1_000_000;
    i64::try_from(v).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_round_trip() {
        let us = parse_seconds_to_micros("1700000000.123456").unwrap();
        assert_eq!(us, 1_700_000_000_123_456);
        assert_eq!(format_epoch(us), "1700000000.123456");
        assert_eq!(parse_seconds_to_micros("-0.5"), Some(-500_000));
        assert_eq!(parse_seconds_to_micros(".25"), Some(250_000));
        assert_eq!(parse_seconds_to_micros("1.1234567"), Some(1_123_456));
        assert_eq!(parse_seconds_to_micros("abc"), None);
        assert_eq!(parse_seconds_to_micros("-"), None);
        assert_eq!(parse_seconds_to_micros("."), None);
        assert_eq!(format_epoch(-1_500_000), "-1.500000");
    }

    #[test]
    fn iso_round_trip() {
        let us = parse_iso("2023-11-14T22:13:20.5Z").unwrap();
        assert_eq!(us, 1_700_000_000_500_000);
        assert_eq!(format_iso(us), "2023-11-14T22:13:20.500000Z");
        assert_eq!(format_iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(parse_iso("1970-01-02"), Some(86_400_000_000));
        assert_eq!(
            parse_iso("2023-11-14T23:13:20+01:00"),
            Some(1_700_000_000_000_000)
        );
        assert_eq!(
            parse_iso("2023-11-14T21:13:20-01:00"),
            Some(1_700_000_000_000_000)
        );
        assert_eq!(parse_iso("2023-13-01"), None);
        assert_eq!(parse_iso("2023-11-14T25:00:00Z"), None);
        assert_eq!(parse_iso("2023-11-14T22:13:20.Z"), None);
        assert_eq!(parse_iso("2023-11-14T22:13:20 junk"), None);
        assert_eq!(parse_iso("2023/11/14"), None);
        assert_eq!(format_iso(-1), "1969-12-31T23:59:59.999999Z");
        assert_eq!(
            parse_epoch_or_iso("2023-11-14T22:13:20Z"),
            Some(1_700_000_000_000_000)
        );
        assert_eq!(
            parse_epoch_or_iso("1700000000"),
            Some(1_700_000_000_000_000)
        );
    }

    #[test]
    fn civil_inverse() {
        for d in [-800_000, -1, 0, 1, 19_000, 2_932_896] {
            let (y, m, dd) = civil_from_days(d);
            assert_eq!(days_from_civil(y, m, dd), d);
        }
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration_literal("250ms"), Some(250_000));
        assert_eq!(parse_duration_literal("1.5m"), Some(90_000_000));
        assert_eq!(parse_duration_literal("7d"), Some(604_800_000_000));
        assert_eq!(parse_duration_literal("100us"), Some(100));
        assert_eq!(parse_duration_literal("3x"), None);
        assert_eq!(parse_duration_literal("12"), None);
        assert_eq!(format_duration(3_723_000_000), "1h2m3s");
        assert_eq!(format_duration(1_500_000), "1.5s");
        assert_eq!(format_duration(250_000), "250ms");
        assert_eq!(format_duration(12), "12us");
        assert_eq!(format_duration(-2_000_000), "-2s");
        assert_eq!(format_duration(90_061_000_000), "1d1h1m1s");
        assert_eq!(format_duration(3_600_500_000), "1h");
    }
}
