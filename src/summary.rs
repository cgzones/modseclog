use std::{net::IpAddr, str::FromStr};

use crate::{
    HttpStatusCode, ModSecurityEvent, RuleId, event_filter::DisplayRuleSeverity,
    mod_security::HttpStatus,
};

use hashbrown::HashMap;
use ipnet::IpNet;
use time::OffsetDateTime;

type CountMap<T> = HashMap<T, u64>;
type CountVec<T> = Vec<(T, u64)>;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum IpDetail {
    Single(IpAddr),
    Cidr(IpNet),
}

impl IpDetail {
    #[must_use]
    pub(crate) fn contains(&self, needle: &IpAddr) -> bool {
        match self {
            Self::Single(ip) => ip == needle,
            Self::Cidr(ipnet) => ipnet.contains(needle),
        }
    }
}

impl FromStr for IpDetail {
    type Err = ipnet::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = s.parse() {
            Ok(Self::Single(ip))
        } else {
            s.parse::<IpNet>().map(Self::Cidr)
        }
    }
}

impl std::fmt::Display for IpDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(ip) => ip.fmt(f),
            Self::Cidr(ipnet) => ipnet.fmt(f),
        }
    }
}

pub(crate) struct RuleIdDesc {
    pub(crate) id: RuleId,
    pub(crate) desc: String,
}

pub(crate) struct Statistics {
    pub(crate) total_events: u64,
    pub(crate) rule_events: u64,
    pub(crate) first_datetime: Option<OffsetDateTime>,
    pub(crate) median_datetime: Option<OffsetDateTime>,
    pub(crate) last_datetime: Option<OffsetDateTime>,
    pub(crate) source_ips: CountVec<IpDetail>,
    pub(crate) destination_ips: CountVec<IpDetail>,
    pub(crate) rule_ids: CountVec<RuleIdDesc>,
    pub(crate) rule_severities: CountVec<DisplayRuleSeverity>,
    pub(crate) http_methods: CountVec<String>,
    pub(crate) http_codes: CountVec<HttpStatus>,
    pub(crate) requested_hosts: CountVec<String>,
    pub(crate) requested_paths: CountVec<String>,
}

#[must_use]
pub(crate) fn calc_summary(
    events: &[ModSecurityEvent],
    rule_descriptions: &HashMap<RuleId, String>,
    http_descriptions: &HashMap<HttpStatusCode, String>,
) -> Statistics {
    let mut total_events = 0;
    let mut rule_events = 0;
    let mut first_datetime = None;
    let mut last_datetime = None;
    let mut source_ips = CountMap::new();
    let mut destination_ips = CountMap::new();
    let mut rule_ids = CountMap::new();
    let mut rule_severities = CountMap::new();
    let mut http_methods = CountMap::new();
    let mut http_codes = CountMap::new();
    let mut requested_hosts = CountMap::new();
    let mut requested_paths = CountMap::new();

    debug_assert!(events.is_sorted_by(|a, b| a.date.cmp(&b.date).reverse().is_le()));

    for event in events {
        total_events += 1;

        if let Some(source_ip) = event.source_ip {
            *source_ips.entry(IpDetail::Single(source_ip)).or_default() += 1;
        }

        if let Some(destination_ip) = event.destination_ip {
            *destination_ips
                .entry(IpDetail::Single(destination_ip))
                .or_default() += 1;
        }

        if let Some(rule_details) = &event.rule_details {
            rule_events += 1;

            *rule_ids.entry(rule_details.id).or_default() += 1;

            *rule_severities
                .entry(DisplayRuleSeverity::Some(rule_details.severity))
                .or_default() += 1;
        } else {
            /* Store as rule with no severity */
            *rule_severities
                .entry(DisplayRuleSeverity::None)
                .or_default() += 1;
        }

        if let Some(date) = event.date {
            if first_datetime.is_none_or(|first| date < first) {
                first_datetime = Some(date);
            }

            if last_datetime.is_none_or(|last| date > last) {
                last_datetime = Some(date);
            }
        }

        if let Some(method) = &event.http_method {
            *http_methods.entry_ref(method).or_default() += 1;
        }

        if let Some(status) = &event.http_status {
            *http_codes.entry(&status.code).or_default() += 1;
        }

        if let Some(host) = &event.requested_host {
            *requested_hosts.entry_ref(host).or_default() += 1;
        }

        if let Some(path) = &event.requested_path {
            *requested_paths.entry_ref(path).or_default() += 1;
        }
    }

    let mut source_ips = source_ips.into_iter().collect::<Vec<_>>();
    source_ips.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse());

    let mut destination_ips = destination_ips.into_iter().collect::<Vec<_>>();
    destination_ips.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse());

    let mut rule_ids = rule_ids
        .into_iter()
        .map(|(rule_id, count)| {
            (
                RuleIdDesc {
                    id: rule_id,
                    desc: rule_descriptions
                        .get(&rule_id)
                        .map_or_else(|| String::from("n/a"), std::clone::Clone::clone),
                },
                count,
            )
        })
        .collect::<Vec<_>>();
    rule_ids.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse());

    let mut rule_severities = rule_severities.into_iter().collect::<Vec<_>>();
    rule_severities.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse());

    let mut http_methods = http_methods.into_iter().collect::<Vec<_>>();
    http_methods.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse());

    let mut http_codes = http_codes
        .into_iter()
        .map(|(code, count)| {
            (
                HttpStatus {
                    code: *code,
                    message: http_descriptions
                        .get(code)
                        .map_or_else(|| String::from("n/a"), std::clone::Clone::clone),
                },
                count,
            )
        })
        .collect::<Vec<_>>();
    http_codes.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse());

    let mut requested_hosts = requested_hosts.into_iter().collect::<Vec<_>>();
    requested_hosts.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse());

    let mut requested_paths = requested_paths.into_iter().collect::<Vec<_>>();
    requested_paths.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse());

    let median_datetime = events.get(events.len() / 2).and_then(|e| e.date);

    Statistics {
        total_events,
        rule_events,
        first_datetime,
        median_datetime,
        last_datetime,
        source_ips,
        destination_ips,
        rule_ids,
        rule_severities,
        http_methods,
        http_codes,
        requested_hosts,
        requested_paths,
    }
}
