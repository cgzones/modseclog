use std::fs::File;
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Seek, Take};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use flate2::read::GzDecoder;

use hashbrown::{HashMap, hash_map};
use ratatui::widgets::ListItem;

use regex::Regex;

use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::format_description::well_known::Rfc2822;
use time::macros::format_description;

const BUFFER_SIZE: usize = 8192; /* 8k */
const INPUT_SIZE_LIMIT: u64 = 4 * 1024 * 1024 * 1024; /* 4GiB */

/* 20/Jan/2025:10:08:30.463235 +0100 */
const DATE_FORMAT: &[FormatItem<'_>] = format_description!(
    "[day]/[month repr:short]/[year]:[hour]:[minute]:[second].[subsecond] [offset_hour][offset_minute]"
);
pub(crate) type IpPort = u16;
pub(crate) type RuleId = u32;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum RuleSeverity {
    Critical,
    Error,
    Warning,
    Notice,
}

impl RuleSeverity {
    #[must_use]
    pub(crate) const fn to_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Notice => "notice",
            Self::Warning => "warnings",
        }
    }
}

impl std::fmt::Display for RuleSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl FromStr for RuleSeverity {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CRITICAL" => Ok(Self::Critical),
            "ERROR" => Ok(Self::Error),
            "WARNING" => Ok(Self::Warning),
            "NOTICE" => Ok(Self::Notice),
            _ => Err("Invalid severity"),
        }
    }
}

#[derive(Clone)]
pub(crate) struct RuleDetails {
    pub(crate) id: RuleId,
    pub(crate) description: String,
    pub(crate) severity: RuleSeverity,
    pub(crate) data: Option<String>,
}

pub(crate) type HttpStatusCode = u16;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct HttpStatus {
    pub(crate) code: HttpStatusCode,
    pub(crate) message: String,
}

impl std::fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} - {}", self.code, self.message)
    }
}

#[derive(Clone)]
pub(crate) struct ModSecurityEvent {
    pub(crate) id: String,
    pub(crate) date: Option<OffsetDateTime>,
    pub(crate) source_ip: Option<IpAddr>,
    pub(crate) source_port: Option<IpPort>,
    pub(crate) destination_ip: Option<IpAddr>,
    pub(crate) destination_port: Option<IpPort>,
    pub(crate) requested_host: Option<String>,
    pub(crate) requested_path: Option<String>,
    pub(crate) http_method: Option<String>,
    pub(crate) http_status: Option<HttpStatus>,
    pub(crate) rule_details: Option<RuleDetails>,
    pub(crate) user_agent: Option<String>,
    cached_repr: Option<String>,
}

impl ModSecurityEvent {
    #[must_use]
    const fn new(id: String) -> Self {
        Self {
            id,
            date: None,
            source_ip: None,
            source_port: None,
            destination_ip: None,
            destination_port: None,
            requested_host: None,
            requested_path: None,
            http_method: None,
            http_status: None,
            rule_details: None,
            user_agent: None,
            cached_repr: None,
        }
    }
}

impl<'a> From<&'a ModSecurityEvent> for ListItem<'a> {
    fn from(val: &'a ModSecurityEvent) -> Self {
        ListItem::from(
            val.cached_repr
                .as_ref()
                .expect("should have been created")
                .as_str(),
        )
    }
}

impl std::fmt::Display for ModSecurityEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(date) = self.date {
            write!(
                f,
                "{} ",
                date.format(&Rfc2822).expect("date and format are valid")
            )?;
        }
        if let Some(source_ip) = self.source_ip {
            write!(f, "srcip={source_ip} ")?;
        }
        if let Some(destination_ip) = self.destination_ip {
            write!(f, "dstip={destination_ip} ")?;
        }
        if let Some(rule_details) = &self.rule_details {
            write!(
                f,
                "rid={}[\"{}\"] sev={} ",
                rule_details.id, rule_details.description, rule_details.severity
            )?;
        }
        if let Some(http_status) = &self.http_status {
            write!(f, "code={}[\"{}\"] ", http_status.code, http_status.message)?;
        }
        if let Some(host) = &self.requested_host {
            write!(f, "host={host} ")?;
        }
        if let Some(method) = &self.http_method {
            write!(f, "method={method} ")?;
        }
        if let Some(path) = &self.requested_path {
            write!(f, "path={path} ")?;
        }

        Ok(())
    }
}

#[derive(PartialEq)]
enum Segment {
    A,
    B,
    C,
    E,
    F,
    H,
    I,
    J,
    K,
    Z,
}

impl Segment {
    #[must_use]
    fn new(value: &str) -> Option<Self> {
        match value {
            "A" => Some(Self::A),
            "B" => Some(Self::B),
            "C" => Some(Self::C),
            "E" => Some(Self::E),
            "F" => Some(Self::F),
            "H" => Some(Self::H),
            "I" => Some(Self::I),
            "J" => Some(Self::J),
            "K" => Some(Self::K),
            "Z" => Some(Self::Z),
            _ => None,
        }
    }
}

impl std::fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::B => write!(f, "B"),
            Self::C => write!(f, "C"),
            Self::E => write!(f, "E"),
            Self::F => write!(f, "F"),
            Self::H => write!(f, "H"),
            Self::I => write!(f, "I"),
            Self::J => write!(f, "J"),
            Self::K => write!(f, "K"),
            Self::Z => write!(f, "Z"),
        }
    }
}

pub(crate) enum ParseError {
    Io(std::io::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl From<std::io::Error> for ParseError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

enum MultiBufReader {
    Raw(Take<BufReader<File>>),
    Gz(Take<BufReader<GzDecoder<File>>>),
}

impl MultiBufReader {
    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> io::Result<usize> {
        match self {
            Self::Gz(r) => r.read_until(byte, buf),
            Self::Raw(r) => r.read_until(byte, buf),
        }
    }
}

pub(crate) type ModSecParseRes = (
    Vec<ModSecurityEvent>,
    HashMap<RuleId, String>,
    HashMap<HttpStatusCode, String>,
    Vec<String>,
);

pub(crate) fn parse(path: &Path) -> Result<ModSecParseRes, ParseError> {
    let mut events = Vec::new();
    let mut rule_descriptions = HashMap::new();
    let mut http_descriptions: HashMap<_, String> = HashMap::new();
    let mut warnings = Vec::new();
    let mut file = File::open(path)?;

    let is_gz = if path.extension().is_some_and(|ext| ext == "gz") {
        true
    } else {
        let mut buf = [0; 2];
        if let Err(err) = file.read_exact(&mut buf) {
            if err.kind() != ErrorKind::UnexpectedEof {
                return Err(err.into());
            }
            file.rewind()?;

            false
        } else {
            file.rewind()?;

            buf == [0x1f, 0x8b]
        }
    };

    let mut reader = if is_gz {
        MultiBufReader::Gz(
            BufReader::with_capacity(BUFFER_SIZE, GzDecoder::new(file)).take(INPUT_SIZE_LIMIT),
        )
    } else {
        MultiBufReader::Raw(BufReader::with_capacity(BUFFER_SIZE, file).take(INPUT_SIZE_LIMIT))
    };

    let mut curr_event: Option<ModSecurityEvent> = None;
    let mut curr_segment = Segment::Z;

    /* --544ccf79-A-- */
    let header_re =
        Regex::new(r"^--(?P<identifier>[a-zA-Z0-9]{8})-(?P<segment_type>A|B|C|E|F|H|I|J|K|Z)--$")
            .expect("regex is valid");

    /* [20/Jan/2025:10:08:30.463235 +0100] A42B7cP9_-4N31GLhv8UyABAAVo 1.2.3.4 57761 5.6.7.8 443 */
    let segment_a_pattern = Regex::new(
     r"^\[(?P<timestamp>.+)\] [a-zA-Z0-9_-]+ (?P<source_ip>[0-9.:a-fA-F]+) (?P<source_port>[0-9]+) (?P<destination_ip>[0-9.:a-fA-F]+) (?P<destination_port>[0-9]+)$"
 ).expect("regex is valid");

    /* Host: example.com */
    let segment_b_host_pattern =
        Regex::new(r#"^(?:H|h)ost: (?P<requested_host>\S+)$"#).expect("regex is valid");

    /* GET /sitecore/shell/sitecore.version.xml HTTP/1.1 */
    let segment_b_path_pattern =
        Regex::new(r#"^(?P<http_method>[A-Z]+) (?P<requested_path>\S+)"#).expect("regex is valid");

    /* User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36 */
    let segment_b_user_agent =
        Regex::new(r#"^User-Agent: (?P<user_agent>[^"\t\n\r]+)"#).expect("regex is valid");

    /* HTTP/1.1 404 Not Found */
    let segment_f_status_pattern =
        Regex::new(r#"^\S+ (?P<status_code>[0-9]+) (?P<status_message>.+)$"#)
            .expect("regex is valid");

    /* Message: Warning. Pattern match "^[\\d.:]+$" at REQUEST_HEADERS:Host. [file "/usr/share/modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "735"] [id "920350"] [msg "Host header is a numeric IP address"] [data "1.2.3.4"] [severity "WARNING"] [ver "OWASP_CRS/3.3.7"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] */
    let segment_h_warning_pattern = Regex::new(
    r#"^Message: Warning\. .* \[id "(?P<rule_id>[0-9]+)"\] .*\[msg "(?P<rule_description>[^"\t\n\r]+)"\] (?:\[data "(?P<rule_data>[^"\t\n\r]+)"\] )?.*\[severity "(?P<rule_severity>[A-Z]+)"\].*$"#
  ).expect("regex is valid");

    let mut lineno: u64 = 0;
    let mut data_no_curr_logged = false;

    let mut buf = Vec::with_capacity(BUFFER_SIZE);
    loop {
        buf.clear();
        let bytes = reader.read_until(b'\n', &mut buf)?;
        if bytes == 0 {
            break;
        }

        let line = String::from_utf8_lossy(&buf);
        let line = line.trim();
        lineno += 1;

        if line.is_empty() {
            continue;
        }

        if line.starts_with("--")
            && let Some(caps) = header_re.captures(line)
        {
            let identifier = &caps["identifier"];
            let segment_type = &caps["segment_type"];
            let Some(segment_type) = Segment::new(segment_type) else {
                warnings.push(format!(
                    "{}:{}: invalid segment {}",
                    path.display(),
                    lineno,
                    segment_type
                ));
                continue;
            };

            if curr_segment == segment_type {
                warnings.push(format!(
                    "{}:{}: repeated segment {}",
                    path.display(),
                    lineno,
                    curr_segment
                ));
                continue;
            }

            if segment_type == Segment::A && curr_event.as_ref().is_some_and(|e| e.id == identifier)
            {
                warnings.push(format!(
                    "{}:{}: segment A with same identifier {}",
                    path.display(),
                    lineno,
                    identifier
                ));
            }

            if segment_type == Segment::A && curr_segment != Segment::Z {
                warnings.push(format!(
                    "{}:{}: last segment not closed",
                    path.display(),
                    lineno
                ));
            }

            if segment_type != Segment::A && curr_event.as_ref().is_none_or(|e| e.id != identifier)
            {
                warnings.push(format!(
                    "{}:{}: no opening segment for identifier {}",
                    path.display(),
                    lineno,
                    identifier
                ));
            }

            curr_segment = segment_type;

            match curr_segment {
                Segment::A => {
                    curr_event = Some(ModSecurityEvent::new(identifier.to_string()));
                }
                Segment::Z => {
                    if let Some(mut e) = curr_event.take() {
                        e.cached_repr = Some(e.to_string());
                        events.push(e);
                    } else {
                        warnings.push(format!(
                            "{}:{}: empty event with identifier {}",
                            path.display(),
                            lineno,
                            identifier
                        ));
                    }
                }
                _ => {}
            }

            continue;
        }

        let Some(curr_event) = &mut curr_event else {
            if !data_no_curr_logged {
                warnings.push(format!(
                    "{}:{}: content without opening segment",
                    path.display(),
                    lineno
                ));
            }
            data_no_curr_logged = true;
            continue;
        };
        data_no_curr_logged = false;

        match curr_segment {
            Segment::A => {
                if let Some(caps) = segment_a_pattern.captures(line) {
                    let timestamp = &caps["timestamp"];
                    let source_ip = &caps["source_ip"];
                    let source_port = &caps["source_port"];
                    let destination_ip = &caps["destination_ip"];
                    let destination_port = &caps["destination_port"];

                    match OffsetDateTime::parse(timestamp, &DATE_FORMAT) {
                        Ok(date) => curr_event.date = Some(date),
                        Err(err) => {
                            warnings.push(format!(
                                "{}:{}: invalid timestamp \"{}\": {err}",
                                path.display(),
                                lineno,
                                timestamp,
                            ));
                        }
                    }

                    match source_ip.parse() {
                        Ok(ip) => curr_event.source_ip = Some(ip),
                        Err(err) => {
                            warnings.push(format!(
                                "{}:{}: invalid source IP \"{}\": {err}",
                                path.display(),
                                lineno,
                                source_ip,
                            ));
                        }
                    }

                    match source_port.parse() {
                        Ok(ip) => curr_event.source_port = Some(ip),
                        Err(err) => {
                            warnings.push(format!(
                                "{}:{}: invalid source port \"{}\": {err}",
                                path.display(),
                                lineno,
                                source_port,
                            ));
                        }
                    }

                    match destination_ip.parse() {
                        Ok(ip) => curr_event.destination_ip = Some(ip),
                        Err(err) => {
                            warnings.push(format!(
                                "{}:{}: invalid destination IP \"{}\": {err}",
                                path.display(),
                                lineno,
                                destination_ip,
                            ));
                        }
                    }

                    match destination_port.parse() {
                        Ok(ip) => curr_event.destination_port = Some(ip),
                        Err(err) => {
                            warnings.push(format!(
                                "{}:{}: invalid destination port \"{}\": {err}",
                                path.display(),
                                lineno,
                                destination_port,
                            ));
                        }
                    }
                } else {
                    warnings.push(format!(
                        "{}:{}: invalid segment A content: \"{}\"",
                        path.display(),
                        lineno,
                        line
                    ));
                }
            }
            Segment::B => {
                if curr_event.requested_host.is_none()
                    && let Some(caps) = segment_b_host_pattern.captures(line)
                {
                    let requested_host = &caps["requested_host"];

                    curr_event.requested_host = Some(requested_host.to_string());
                }

                if curr_event.http_method.is_none()
                    && let Some(caps) = segment_b_path_pattern.captures(line)
                {
                    let http_method = &caps["http_method"];
                    let requested_path = &caps["requested_path"];

                    curr_event.http_method = Some(http_method.to_string());
                    curr_event.requested_path = Some(requested_path.to_string());
                }

                if curr_event.user_agent.is_none()
                    && let Some(caps) = segment_b_user_agent.captures(line)
                {
                    let user_agent = &caps["user_agent"];

                    curr_event.user_agent = Some(user_agent.to_string());
                }
            }
            Segment::F => {
                if curr_event.http_status.is_none()
                    && let Some(caps) = segment_f_status_pattern.captures(line)
                {
                    let status_code = &caps["status_code"];
                    let status_message = &caps["status_message"];

                    let status_code = match status_code.parse() {
                        Ok(s) => s,
                        Err(err) => {
                            warnings.push(format!(
                                "{}:{}: invalid HTTP status code \"{}\": {err}",
                                path.display(),
                                lineno,
                                status_code,
                            ));
                            HttpStatusCode::MAX
                        }
                    };

                    curr_event.http_status = Some(HttpStatus {
                        code: status_code,
                        message: status_message.to_string(),
                    });

                    match http_descriptions.entry(status_code) {
                        hash_map::Entry::Occupied(occupied_entry) => {
                            if !status_message.eq_ignore_ascii_case(occupied_entry.get()) {
                                warnings.push(format!(
                                    "{}:{}: different descriptions for http status {}: \"{}\" vs \"{}\"",
                                    path.display(),
                                    lineno,
                                    status_code,
                                    status_message,
                                    occupied_entry.get()
                                ));
                            }
                        }
                        hash_map::Entry::Vacant(vacant_entry) => {
                            vacant_entry.insert(status_message.to_string());
                        }
                    }
                }
            }
            Segment::H => {
                if curr_event.rule_details.is_none()
                    && line.starts_with("Message: Warning. ")
                    && let Some(caps) = segment_h_warning_pattern.captures(line)
                {
                    let rule_id = &caps["rule_id"];
                    let rule_description = &caps["rule_description"];
                    let rule_data = caps.name("rule_data").map(|m| m.as_str().to_string());
                    let rule_severity = &caps["rule_severity"];

                    let rule_id = match rule_id.parse() {
                        Ok(s) => s,
                        Err(err) => {
                            warnings.push(format!(
                                "{}:{}: invalid rule ID \"{}\": {err}",
                                path.display(),
                                lineno,
                                rule_id,
                            ));
                            RuleId::MAX
                        }
                    };

                    let rule_severity = match rule_severity.parse() {
                        Ok(s) => s,
                        Err(err) => {
                            warnings.push(format!(
                                "{}:{}: invalid rule severity \"{}\": {err}",
                                path.display(),
                                lineno,
                                rule_severity,
                            ));
                            RuleSeverity::Critical
                        }
                    };

                    curr_event.rule_details = Some(RuleDetails {
                        id: rule_id,
                        description: rule_description.to_string(),
                        severity: rule_severity,
                        data: rule_data,
                    });

                    match rule_descriptions.entry(rule_id) {
                        hash_map::Entry::Occupied(occupied_entry) => {
                            if rule_description != *occupied_entry.get() {
                                warnings.push(format!(
                                    "{}:{}: different descriptions for rule ID {}: \"{}\" vs \"{}\"",
                                    path.display(),
                                    lineno,
                                    rule_id,
                                    rule_description,
                                    occupied_entry.get()
                                ));
                            }
                        }
                        hash_map::Entry::Vacant(vacant_entry) => {
                            vacant_entry.insert(rule_description.to_string());
                        }
                    }
                }
            }
            Segment::Z => {
                warnings.push(format!(
                    "{}:{}: invalid segment Z content: \"{}\"",
                    path.display(),
                    lineno,
                    line
                ));
            }
            Segment::C | Segment::E | Segment::I | Segment::J | Segment::K =>
                /* ignore for now */
                {}
        }
    }

    Ok((events, rule_descriptions, http_descriptions, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_parsing() {
        let timestamp = "20/Jan/2025:10:08:30.463235 +0100";
        let date = OffsetDateTime::parse(timestamp, &DATE_FORMAT).unwrap();
        assert_eq!("2025-01-20 10:08:30.463235 +01:00:00", format!("{date}"));
    }
}
