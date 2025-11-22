use crate::{
    HttpStatusCode, ModSecurityEvent, RuleId, mod_security::RuleSeverity, summary::IpDetail,
};

pub(crate) trait EventFilterImpl: Clone + Eq {
    #[must_use]
    fn apply(&self, event: &ModSecurityEvent) -> bool;
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum EventFilter {
    SourceIpExclude(SourceIpExclude),
    SourceIpMatch(SourceIpMatch),
    DestinationIpExclude(DestinationIpExclude),
    DestinationIpMatch(DestinationIpMatch),
    HttpStatusExclude(HttpStatusExclude),
    HttpStatusMatch(HttpStatusMatch),
    HttpMethodExclude(HttpMethodExclude),
    HttpMethodMatch(HttpMethodMatch),
    RuleIdExclude(RuleIdExclude),
    RuleIdMatch(RuleIdMatch),
    RuleSeverityExclude(RuleSeverityExclude),
    RuleSeverityMatch(RuleSeverityMatch),
    RequestedHostExclude(RequestedHostExclude),
    RequestedHostMatch(RequestedHostMatch),
    RequestedPathExclude(RequestedPathExclude),
    RequestedPathMatch(RequestedPathMatch),
}

impl EventFilterImpl for EventFilter {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        match self {
            Self::SourceIpExclude(f) => f.apply(event),
            Self::SourceIpMatch(f) => f.apply(event),
            Self::DestinationIpExclude(f) => f.apply(event),
            Self::DestinationIpMatch(f) => f.apply(event),
            Self::HttpStatusExclude(f) => f.apply(event),
            Self::HttpStatusMatch(f) => f.apply(event),
            Self::HttpMethodExclude(f) => f.apply(event),
            Self::HttpMethodMatch(f) => f.apply(event),
            Self::RuleIdExclude(f) => f.apply(event),
            Self::RuleIdMatch(f) => f.apply(event),
            Self::RuleSeverityExclude(f) => f.apply(event),
            Self::RuleSeverityMatch(f) => f.apply(event),
            Self::RequestedHostExclude(f) => f.apply(event),
            Self::RequestedHostMatch(f) => f.apply(event),
            Self::RequestedPathExclude(f) => f.apply(event),
            Self::RequestedPathMatch(f) => f.apply(event),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SourceIpExclude {
    pub(crate) ipnet: IpDetail,
}

impl EventFilterImpl for SourceIpExclude {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event.source_ip.is_none_or(|ip| !self.ipnet.contains(&ip))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SourceIpMatch {
    pub(crate) ipnets: Vec<IpDetail>,
}

impl EventFilterImpl for SourceIpMatch {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .source_ip
            .is_some_and(|ip| self.ipnets.iter().any(|ipdetail| ipdetail.contains(&ip)))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DestinationIpExclude {
    pub(crate) ipnet: IpDetail,
}

impl EventFilterImpl for DestinationIpExclude {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .destination_ip
            .is_none_or(|ip| !self.ipnet.contains(&ip))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DestinationIpMatch {
    pub(crate) ipnets: Vec<IpDetail>,
}

impl EventFilterImpl for DestinationIpMatch {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .destination_ip
            .is_some_and(|ip| self.ipnets.iter().any(|ipnet| ipnet.contains(&ip)))
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum DisplayRuleSeverity {
    Some(RuleSeverity),
    None,
}

impl DisplayRuleSeverity {
    #[must_use]
    const fn is_some(self) -> bool {
        match self {
            Self::Some(_) => true,
            Self::None => false,
        }
    }

    #[must_use]
    pub(crate) const fn to_str(self) -> &'static str {
        match self {
            Self::Some(r) => r.to_str(),
            Self::None => "<none>",
        }
    }
}

impl std::fmt::Display for DisplayRuleSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RuleSeverityExclude {
    pub(crate) sev: DisplayRuleSeverity,
}

impl EventFilterImpl for RuleSeverityExclude {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        match event.rule_details.as_ref() {
            Some(rd) => DisplayRuleSeverity::Some(rd.severity) != self.sev,
            None => self.sev.is_some(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RuleSeverityMatch {
    pub(crate) sevs: Vec<DisplayRuleSeverity>,
}

impl EventFilterImpl for RuleSeverityMatch {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        match event.rule_details.as_ref() {
            Some(rd) => self.sevs.contains(&DisplayRuleSeverity::Some(rd.severity)),
            None => self.sevs.contains(&DisplayRuleSeverity::None),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RuleIdExclude {
    pub(crate) id: RuleId,
}

impl EventFilterImpl for RuleIdExclude {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .rule_details
            .as_ref()
            .is_none_or(|rd| rd.id != self.id)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RuleIdMatch {
    pub(crate) ids: Vec<RuleId>,
}

impl EventFilterImpl for RuleIdMatch {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .rule_details
            .as_ref()
            .is_some_and(|rd| self.ids.contains(&rd.id))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct HttpStatusExclude {
    pub(crate) code: HttpStatusCode,
}

impl EventFilterImpl for HttpStatusExclude {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .http_status
            .as_ref()
            .is_none_or(|st| st.code != self.code)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct HttpStatusMatch {
    pub(crate) codes: Vec<HttpStatusCode>,
}

impl EventFilterImpl for HttpStatusMatch {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .http_status
            .as_ref()
            .is_some_and(|st| self.codes.contains(&st.code))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct HttpMethodExclude {
    pub(crate) method: String,
}

impl EventFilterImpl for HttpMethodExclude {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .http_method
            .as_ref()
            .is_none_or(|st| *st != self.method)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct HttpMethodMatch {
    pub(crate) methods: Vec<String>,
}

impl EventFilterImpl for HttpMethodMatch {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .http_method
            .as_ref()
            .is_some_and(|st| self.methods.contains(st))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RequestedHostExclude {
    pub(crate) host: String,
}

impl EventFilterImpl for RequestedHostExclude {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .requested_host
            .as_ref()
            .is_none_or(|st| st != &self.host)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RequestedHostMatch {
    pub(crate) hosts: Vec<String>,
}

impl EventFilterImpl for RequestedHostMatch {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .requested_host
            .as_ref()
            .is_some_and(|st| self.hosts.contains(st))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RequestedPathExclude {
    pub(crate) path: String,
}

impl EventFilterImpl for RequestedPathExclude {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .requested_path
            .as_ref()
            .is_none_or(|st| st != &self.path)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RequestedPathMatch {
    pub(crate) paths: Vec<String>,
}

impl EventFilterImpl for RequestedPathMatch {
    fn apply(&self, event: &ModSecurityEvent) -> bool {
        event
            .requested_path
            .as_ref()
            .is_some_and(|st| self.paths.contains(st))
    }
}
