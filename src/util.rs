// SPDX-License-Identifier: GPL-3.0-or-later

//! Small helpers that reproduce Go standard-library behaviour the CLI
//! exposes: size and duration parsing and printing, `path.Clean`, RFC 3339
//! timestamps, and Go-style I/O error messages.

use std::path::Path;
use std::time::Duration;

/// `op path: reason`, with the OS reason lower-cased and without Rust's
/// "(os error N)" suffix, as Go prints a `*PathError`.
pub fn io_msg(op: &str, path: &Path, e: &std::io::Error) -> String {
    format!("{op} {}: {}", path.display(), io_reason(e))
}

pub fn io_reason(e: &std::io::Error) -> String {
    let s = e.to_string();
    let s = match s.find(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    };
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().chain(c).collect(),
        None => s,
    }
}

/// `humanSize`: bytes below 1 KiB, otherwise one decimal and a binary unit.
pub fn human_size(n: u64) -> String {
    const UNIT: u64 = 1024;
    if n < UNIT {
        return format!("{n} B");
    }
    let (mut div, mut exp) = (UNIT, 0usize);
    let mut m = n / UNIT;
    while m >= UNIT {
        div *= UNIT;
        exp += 1;
        m /= UNIT;
    }
    format!("{:.1} {}iB", n as f64 / div as f64, &"KMGTPE"[exp..exp + 1])
}

/// `parseSize`: a byte count with optional K, M, G or T (powers of 1024)
/// and an optional trailing B, at most 1 TiB.
pub fn parse_size(s: &str, limit: u64) -> Result<u64, String> {
    let err = || format!("invalid size {s:?}");
    let upper = s.to_uppercase();
    let mut num = upper.strip_suffix('B').unwrap_or(&upper).to_string();
    let mut shift = 0u32;
    for (i, unit) in "KMGT".chars().enumerate() {
        if let Some(rest) = num.strip_suffix(unit) {
            num = rest.to_string();
            shift = 10 * (i as u32 + 1);
        }
    }
    let n = go_parse_int(&num).ok_or_else(err)?;
    if n < 0 || n as u64 > limit >> shift {
        return Err(err());
    }
    Ok((n as u64) << shift)
}

/// Go's `strconv.ParseInt(s, 10, 64)`: optional sign, decimal digits.
fn go_parse_int(s: &str) -> Option<i64> {
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let v: i128 = digits.parse().ok()?;
    let v = if neg { -v } else { v };
    i64::try_from(v).ok()
}

/// Go's `time.ParseDuration`, in nanoseconds.
pub fn parse_duration(s: &str) -> Result<i64, String> {
    let err = || format!("time: invalid duration {:?}", s);
    let orig = s;
    let mut s = s;
    let mut neg = false;
    if let Some(c @ ('-' | '+')) = s.chars().next() {
        neg = c == '-';
        s = &s[1..];
    }
    if s == "0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(err());
    }
    let mut total: u128 = 0;
    while !s.is_empty() {
        let int_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let int_part = &s[..int_end];
        s = &s[int_end..];
        let mut frac_part = "";
        if let Some(rest) = s.strip_prefix('.') {
            let fe = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            frac_part = &rest[..fe];
            s = &rest[fe..];
            if int_part.is_empty() && frac_part.is_empty() {
                return Err(err());
            }
        } else if int_part.is_empty() {
            return Err(err());
        }
        let ue = s.find(|c: char| c == '.' || c.is_ascii_digit()).unwrap_or(s.len());
        let unit = &s[..ue];
        s = &s[ue..];
        let scale: u128 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            "" => return Err(format!("time: missing unit in duration {orig:?}")),
            _ => return Err(format!("time: unknown unit {unit:?} in duration {orig:?}")),
        };
        let v: u128 = if int_part.is_empty() {
            0
        } else {
            int_part.parse().map_err(|_| err())?
        };
        let mut ns = v.checked_mul(scale).ok_or_else(err)?;
        if !frac_part.is_empty() {
            // Go truncates the fraction to the unit's precision.
            let mut f: u128 = 0;
            let mut div: u128 = 1;
            for c in frac_part.bytes() {
                if div > 1_000_000_000_000_000_000 {
                    break;
                }
                f = f * 10 + (c - b'0') as u128;
                div *= 10;
            }
            ns += f * scale / div;
        }
        total = total.checked_add(ns).ok_or_else(err)?;
        if total > i64::MAX as u128 + neg as u128 {
            return Err(err());
        }
    }
    Ok(if neg { (total as i128).wrapping_neg() as i64 } else { total as i64 })
}

/// Go's `time.Duration.String` for non-negative durations.
pub fn format_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns == 0 {
        return "0s".into();
    }
    if ns < 1_000_000_000 {
        let (unit, div, prec) = if ns < 1_000 {
            ("ns", 1u128, 0)
        } else if ns < 1_000_000 {
            ("µs", 1_000, 3)
        } else {
            ("ms", 1_000_000, 6)
        };
        return format!("{}{unit}", frac(ns, div, prec));
    }
    let mut out = String::new();
    let h = ns / 3_600_000_000_000;
    let m = (ns / 60_000_000_000) % 60;
    let s_ns = ns % 60_000_000_000;
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if h > 0 || m > 0 {
        out.push_str(&format!("{m}m"));
    }
    out.push_str(&format!("{}s", frac(s_ns, 1_000_000_000, 9)));
    out
}

fn frac(v: u128, div: u128, prec: usize) -> String {
    let whole = v / div;
    let f = v % div;
    if f == 0 || prec == 0 {
        return whole.to_string();
    }
    let mut digits = format!("{f:0prec$}");
    while digits.ends_with('0') {
        digits.pop();
    }
    format!("{whole}.{digits}")
}

/// Go's `path.Clean` for slash-separated paths.
pub fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|l| *l != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            s => parts.push(s),
        }
    }
    let body = parts.join("/");
    match (rooted, body.is_empty()) {
        (true, _) => format!("/{body}"),
        (false, true) => ".".into(),
        (false, false) => body,
    }
}

/// Go's `path.Base`.
pub fn base(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "/".into();
    }
    t.rsplit('/').next().unwrap_or(t).to_string()
}

/// Go's `path.Join`: join non-empty elements with '/', then clean.
pub fn join(parts: &[&str]) -> String {
    let nonempty: Vec<&str> = parts.iter().copied().filter(|p| !p.is_empty()).collect();
    if nonempty.is_empty() {
        return String::new();
    }
    clean(&nonempty.join("/"))
}

/// A UTC instant with nanosecond precision, as stored in records.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Instant {
    pub secs: i64,
    pub nanos: u32,
}

impl Instant {
    pub fn now() -> Self {
        Self::from_system(std::time::SystemTime::now())
    }

    pub fn from_system(t: std::time::SystemTime) -> Self {
        match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => Instant {
                secs: d.as_secs() as i64,
                nanos: d.subsec_nanos(),
            },
            Err(e) => {
                let d = e.duration();
                let (s, n) = (d.as_secs() as i64, d.subsec_nanos());
                if n == 0 {
                    Instant { secs: -s, nanos: 0 }
                } else {
                    Instant {
                        secs: -s - 1,
                        nanos: 1_000_000_000 - n,
                    }
                }
            }
        }
    }

    pub fn to_system(self) -> std::time::SystemTime {
        if self.secs >= 0 {
            std::time::UNIX_EPOCH + Duration::new(self.secs as u64, self.nanos)
        } else {
            std::time::UNIX_EPOCH - Duration::new(self.secs.unsigned_abs(), 0) + Duration::new(0, self.nanos)
        }
    }

    fn timestamp(self) -> Option<jiff::Timestamp> {
        // jiff wants both parts to share a sign.
        if self.secs < 0 && self.nanos > 0 {
            jiff::Timestamp::new(self.secs + 1, self.nanos as i32 - 1_000_000_000).ok()
        } else {
            jiff::Timestamp::new(self.secs, self.nanos as i32).ok()
        }
    }

    /// RFC 3339 with up to nine fractional digits, trailing zeros removed,
    /// and "Z": Go's `time.RFC3339Nano` for a UTC time. None outside years
    /// 0 to 9999, which Go's JSON encoding refuses too.
    pub fn to_rfc3339(self) -> Option<String> {
        let days = self.secs.div_euclid(86_400);
        let sod = self.secs.rem_euclid(86_400);
        let (y, mo, d) = civil_from_days(days);
        if !(0..=9999).contains(&y) {
            return None;
        }
        let mut s = format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}", sod / 3600, sod / 60 % 60, sod % 60);
        if self.nanos != 0 {
            let mut f = format!("{:09}", self.nanos);
            while f.ends_with('0') {
                f.pop();
            }
            s.push('.');
            s.push_str(&f);
        }
        s.push('Z');
        Some(s)
    }

    /// Strict RFC 3339 (`YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)`), as
    /// Go's `time.Time.UnmarshalJSON` accepts it.
    pub fn parse_rfc3339(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        let num = |r: std::ops::Range<usize>| -> Option<i64> {
            let t = b.get(r)?;
            if t.iter().all(u8::is_ascii_digit) {
                std::str::from_utf8(t).ok()?.parse().ok()
            } else {
                None
            }
        };
        if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
            return None;
        }
        let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
        if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || se > 59 {
            return None;
        }
        let mut i = 19;
        let mut nanos = 0u32;
        if b[i] == b'.' {
            let start = i + 1;
            i = start;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let digits = &s[start..i];
            if digits.is_empty() || digits.len() > 9 {
                return None;
            }
            nanos = format!("{digits:0<9}").parse().ok()?;
        }
        let offset = match &b[i..] {
            b"Z" => 0,
            [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
                let oh = num(i + 1..i + 3)?;
                let om = num(i + 4..i + 6)?;
                if oh > 23 || om > 59 {
                    return None;
                }
                let o = oh * 3600 + om * 60;
                if *sign == b'-' { -o } else { o }
            }
            _ => return None,
        };
        let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se - offset;
        Some(Instant { secs, nanos })
    }

    /// "2006-01-02 15:04" in the local time zone, as `ls` and `list` show.
    pub fn local_minute(self) -> String {
        match self.timestamp() {
            Some(ts) => {
                let z = ts.to_zoned(jiff::tz::TimeZone::system());
                format!("{:04}-{:02}-{:02} {:02}:{:02}", z.year(), z.month(), z.day(), z.hour(), z.minute())
            }
            None => "????-??-?? ??:??".into(),
        }
    }

    /// "15:04:05" local, for unlock's message.
    pub fn local_clock(self) -> String {
        match self.timestamp() {
            Some(ts) => {
                let z = ts.to_zoned(jiff::tz::TimeZone::system());
                format!("{:02}:{:02}:{:02}", z.hour(), z.minute(), z.second())
            }
            None => "??:??:??".into(),
        }
    }
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn v() -> Value {
        serde_json::from_str(include_str!("../tests/vectors/store.json")).unwrap()
    }

    #[test]
    fn sizes_match_go() {
        let v = v();
        for (input, want) in v["parse_size"].as_object().unwrap() {
            let got = parse_size(input, 1 << 40).ok();
            assert_eq!(got, want.as_u64(), "parseSize({input:?})");
        }
        for (n, want) in v["human_size"].as_object().unwrap() {
            assert_eq!(human_size(n.parse().unwrap()), want.as_str().unwrap(), "humanSize({n})");
        }
    }

    #[test]
    fn durations_match_go() {
        for (input, want) in v()["durations"].as_object().unwrap() {
            let got = parse_duration(input).ok();
            match want {
                Value::Null => assert_eq!(got, None, "ParseDuration({input:?})"),
                w => {
                    let ns = w["ns"].as_i64().unwrap();
                    assert_eq!(got, Some(ns), "ParseDuration({input:?})");
                    if ns >= 0 {
                        assert_eq!(format_duration(Duration::from_nanos(ns as u64)), w["string"].as_str().unwrap());
                    }
                }
            }
        }
    }

    #[test]
    fn clean_matches_go() {
        for (input, want) in v()["path_clean"].as_object().unwrap() {
            assert_eq!(clean(input), want.as_str().unwrap(), "Clean({input:?})");
        }
        assert_eq!(base("a/b/"), "b");
        assert_eq!(base("/"), "/");
        assert_eq!(join(&["", "a", "b/../c"]), "a/c");
    }

    #[test]
    fn rfc3339() {
        for (s, n) in [
            (0, 0),
            (1700000000, 123456789),
            (-1, 500000000),
            (253402300799, 999999999),
            (1234567890, 120000000),
        ] {
            let t = Instant { secs: s, nanos: n };
            let text = t.to_rfc3339().unwrap();
            assert_eq!(Instant::parse_rfc3339(&text), Some(t), "{text}");
        }
        assert_eq!(
            Instant {
                secs: 1234567890,
                nanos: 120000000
            }
            .to_rfc3339()
            .unwrap(),
            "2009-02-13T23:31:30.12Z"
        );
        assert_eq!(Instant::parse_rfc3339("2009-02-13T23:31:30+01:00").unwrap().secs, 1234567890 - 3600);
        for bad in [
            "2009-02-13 23:31:30Z",
            "2009-02-13T23:31:30",
            "2009-02-13T23:31:30.Z",
            "2009-13-13T23:31:30Z",
            "2009-02-13T23:31:30.1234567890Z",
        ] {
            assert_eq!(Instant::parse_rfc3339(bad), None, "{bad}");
        }
        assert_eq!(
            Instant {
                secs: 253402300800,
                nanos: 0
            }
            .to_rfc3339(),
            None
        );
        assert_eq!(
            Instant {
                secs: -62167219200,
                nanos: 0
            }
            .to_rfc3339()
            .unwrap(),
            "0000-01-01T00:00:00Z"
        );
        assert_eq!(
            Instant {
                secs: -62167219201,
                nanos: 0
            }
            .to_rfc3339(),
            None
        );
        assert_eq!(Instant::parse_rfc3339("2023-02-29T00:00:00Z"), None);
        assert!(Instant::parse_rfc3339("2024-02-29T00:00:00Z").is_some());
        let neg = Instant::from_system(std::time::UNIX_EPOCH - Duration::new(0, 1));
        assert_eq!(
            neg,
            Instant {
                secs: -1,
                nanos: 999_999_999
            }
        );
        assert_eq!(Instant::from_system(neg.to_system()), neg);
    }
}
