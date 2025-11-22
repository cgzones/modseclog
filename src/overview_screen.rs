use std::io;
use std::num::{ParseIntError, Saturating, Wrapping};
use std::sync::{Arc, mpsc};

use crate::event_filter::{
    DestinationIpExclude, DestinationIpMatch, DisplayRuleSeverity, HttpMethodExclude,
    HttpMethodMatch, HttpStatusExclude, HttpStatusMatch, RequestedHostExclude, RequestedHostMatch,
    RequestedPathExclude, RequestedPathMatch, RuleIdExclude, RuleIdMatch, RuleSeverityExclude,
    RuleSeverityMatch, SourceIpExclude, SourceIpMatch,
};
use crate::mod_security::{HttpStatus, HttpStatusCode, RuleId, RuleSeverity};
use crate::ratatui_utils::{popup_area_absolute, popup_area_percent};
use crate::style::{
    ACTIVE_ENTRY_HIGHLIGHT_STYLE, HEADER_ACTIVE_STYLE, HEADER_INACTIVE_STYLE, HIDDEN_STYLE,
    INACTIVE_ENTRY_HIGHLIGHT_STYLE, KEY_HINT_STYLE, PANEL_HINT_STYLE, PROGRAM_TITLE_STYLE,
    SCROLL_COUNT,
};
use crate::summary::{IpDetail, RuleIdDesc};
use crate::utils::contains_case_insensitive;
use crate::{AppEvent, AppTask, EventFilter, ModSecurityEvent, Statistics, Succession};

use hashbrown::HashMap;
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use fuzzy_matcher::{FuzzyMatcher as _, skim::SkimMatcherV2};

use ratatui::DefaultTerminal;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::prelude::*;
use ratatui::style::Color::DarkGray;
use ratatui::style::Style;
use ratatui::symbols::border;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::ListItem;
use ratatui::widgets::{
    Block, Cell, Clear, List, ListState, Paragraph, Row, StatefulWidget, StatefulWidgetRef, Table,
    TableState, Widget, Wrap,
};
use ratatui::widgets::{BorderType, WidgetRef};

use time::format_description::well_known::Rfc2822;

macro_rules! vec_del {
    ($vec: expr, $item: ident) => {
        for (idx, entry) in $vec.iter().enumerate() {
            if *entry == $item {
                $vec.remove(idx);
                break;
            }
        }
    };
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ActivePanel {
    SourceIp,
    DestinationIp,
    HttpStatus,
    HttpMethod,
    RuleSeverity,
    RuleId,
    RequestedHost,
    RequestedPath,
    EventsPanel,
    WarningsPanel,
    None,
}

impl ActivePanel {
    #[must_use]
    const fn next(self) -> Self {
        match self {
            Self::None => Self::SourceIp,
            Self::SourceIp => Self::DestinationIp,
            Self::DestinationIp => Self::HttpStatus,
            Self::HttpStatus => Self::HttpMethod,
            Self::HttpMethod => Self::RuleId,
            Self::RuleId => Self::RuleSeverity,
            Self::RuleSeverity => Self::RequestedHost,
            Self::RequestedHost => Self::RequestedPath,
            Self::RequestedPath => Self::EventsPanel,
            Self::EventsPanel => Self::WarningsPanel,
            Self::WarningsPanel => Self::None,
        }
    }

    #[must_use]
    const fn previous(self) -> Self {
        match self {
            Self::None => Self::WarningsPanel,
            Self::SourceIp => Self::None,
            Self::DestinationIp => Self::SourceIp,
            Self::HttpStatus => Self::DestinationIp,
            Self::HttpMethod => Self::HttpStatus,
            Self::RuleId => Self::HttpMethod,
            Self::RuleSeverity => Self::RuleId,
            Self::RequestedHost => Self::RuleSeverity,
            Self::RequestedPath => Self::RequestedHost,
            Self::EventsPanel => Self::RequestedPath,
            Self::WarningsPanel => Self::EventsPanel,
        }
    }

    #[must_use]
    fn hint(self) -> Line<'static> {
        let s = match self {
            Self::None => unreachable!(),
            Self::SourceIp => "1",
            Self::DestinationIp => "2",
            Self::HttpStatus => "3",
            Self::HttpMethod => "4",
            Self::RuleId => "5",
            Self::RuleSeverity => "6",
            Self::RequestedHost => "7",
            Self::RequestedPath => "8",
            Self::EventsPanel => "9",
            Self::WarningsPanel => "0",
        };
        Line::from(s).right_aligned().style(PANEL_HINT_STYLE)
    }

    #[must_use]
    const fn from_id(id: char) -> Option<Self> {
        match id {
            '1' => Some(Self::SourceIp),
            '2' => Some(Self::DestinationIp),
            '3' => Some(Self::HttpStatus),
            '4' => Some(Self::HttpMethod),
            '5' => Some(Self::RuleId),
            '6' => Some(Self::RuleSeverity),
            '7' => Some(Self::RequestedHost),
            '8' => Some(Self::RequestedPath),
            '9' => Some(Self::EventsPanel),
            '0' => Some(Self::WarningsPanel),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum AddFilterKind {
    SourceIpMatch,
    SourceIpExclude,
}

#[derive(Clone, Copy)]
enum Action {
    None,
    FilterUpdate,
    AddFilter(AddFilterKind, usize),
    ShowEventDetails(usize),
    CustomInput,
    Search,
    Unselect,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EventVisibility {
    Hidden,
    Partial,
    Full,
}

impl EventVisibility {
    #[must_use]
    const fn next(self) -> Self {
        match self {
            Self::Hidden => Self::Partial,
            Self::Partial => Self::Full,
            Self::Full => Self::Hidden,
        }
    }

    #[must_use]
    const fn previous(self) -> Self {
        match self {
            Self::Hidden => Self::Full,
            Self::Partial => Self::Hidden,
            Self::Full => Self::Partial,
        }
    }
}

#[expect(clippy::large_enum_variant)]
enum FilteredData {
    Filtered(Vec<ModSecurityEvent>, Statistics),
    Unfiltered,
    Loading,
}

pub(crate) struct OverviewScreen {
    task_tx: mpsc::Sender<AppTask>,
    parsed_events: Arc<[ModSecurityEvent]>,
    filtered: FilteredData,
    warnings: Vec<String>,
    rule_descriptions: Arc<HashMap<RuleId, String>>,
    http_descriptions: Arc<HashMap<HttpStatusCode, String>>,
    parsed_stats: Option<Statistics>,
    show_events: EventVisibility,
    show_warnings: bool,
    quit_popup: bool,
    active_panel: ActivePanel,
    filters: Vec<EventFilter>,
    seqno: Wrapping<u32>,
}

macro_rules! filtered {
    ($id: ident) => {
        match &$id.filtered {
            FilteredData::Filtered(data, stats) => Some((data.as_slice(), stats)),
            FilteredData::Unfiltered => match $id.parsed_stats.as_ref() {
                Some(s) => Some((&*$id.parsed_events, s)),
                None => None,
            },
            FilteredData::Loading => None,
        }
    };
}

impl OverviewScreen {
    #[must_use]
    pub(crate) fn new(
        parsed_events: Vec<ModSecurityEvent>,
        rule_descriptions: HashMap<RuleId, String>,
        http_descriptions: HashMap<HttpStatusCode, String>,
        warnings: Vec<String>,
        task_tx: mpsc::Sender<AppTask>,
    ) -> Self {
        let show_events = if parsed_events.is_empty() {
            EventVisibility::Hidden
        } else {
            EventVisibility::Partial
        };

        let parsed_events = Arc::from(parsed_events);
        let rule_descriptions = Arc::new(rule_descriptions);
        let http_descriptions = Arc::new(http_descriptions);

        task_tx
            .send(AppTask::CalcSummary(
                Arc::clone(&parsed_events),
                Arc::clone(&rule_descriptions),
                Arc::clone(&http_descriptions),
            ))
            .expect("task thread should not die before TUI thread");

        Self {
            show_events,
            parsed_stats: None,
            filtered: FilteredData::Unfiltered,
            parsed_events,
            show_warnings: !warnings.is_empty(),
            warnings,
            quit_popup: false,
            rule_descriptions,
            http_descriptions,
            active_panel: ActivePanel::None,
            filters: Vec::new(),
            task_tx,
            seqno: Wrapping(0),
        }
    }

    pub(crate) fn run(
        &mut self,
        terminal: &mut DefaultTerminal,
        event_rx: &mpsc::Receiver<AppEvent>,
    ) -> io::Result<Succession> {
        let mut overview_widget = None;
        let quit_popup_widget = QuitPopupWidget::new();
        let mut event_popup_widget: Option<EventPopupWidget<'_>> = None;
        let mut custom_input_popup_widget: Option<CustomInputPopupWidget<'_>> = None;
        let mut search_popup_widget: Option<SearchPopupWidget> = None;

        let mut warnings_widget_state = ListState::default();
        let mut events_widget_state = ListState::default();
        let mut custom_input_popup_state = CustomInputPopupState::new(Vec::new());
        let mut search_popup_state = SearchPopupState::new(Vec::new());

        let mut source_ip_state = DetailState::new();
        let mut destination_ip_state = DetailState::new();
        let mut rule_id_state = DetailState::new();
        let mut rule_severity_state = DetailState::new();
        let mut http_status_state = DetailState::new();
        let mut http_method_state = DetailState::new();
        let mut requested_host_state = DetailState::new();
        let mut requested_path_state = DetailState::new();

        let mut rebuild_filters = false;

        loop {
            /* do not show event popup when no events available */
            assert!(
                event_popup_widget.is_none() || filtered!(self).is_some_and(|fe| !fe.0.is_empty())
            );

            /* only one popup */
            #[expect(clippy::unnested_or_patterns)]
            {
                assert!(matches!(
                    (
                        custom_input_popup_widget.is_some(),
                        search_popup_widget.is_some(),
                        event_popup_widget.is_some(),
                    ),
                    (false, false, false)
                        | (true, false, false)
                        | (false, true, false)
                        | (false, false, true)
                ));
            }

            if rebuild_filters {
                events_widget_state.select(None);
                event_popup_widget = None;
                overview_widget = None;

                if let Some(parsed_stats) = &self.parsed_stats {
                    let mut filters = Vec::new();
                    filters.extend(SourceIpWidget::build_filters(
                        parsed_stats,
                        &source_ip_state,
                    ));
                    filters.extend(DestinationIpWidget::build_filters(
                        parsed_stats,
                        &destination_ip_state,
                    ));
                    filters.extend(RuleIdWidget::build_filters(parsed_stats, &rule_id_state));
                    filters.extend(RuleSeverityWidget::build_filters(
                        parsed_stats,
                        &rule_severity_state,
                    ));
                    filters.extend(HttpStatusWidget::build_filters(
                        parsed_stats,
                        &http_status_state,
                    ));
                    filters.extend(HttpMethodWidget::build_filters(
                        parsed_stats,
                        &http_method_state,
                    ));
                    filters.extend(RequestedHostWidget::build_filters(
                        parsed_stats,
                        &requested_host_state,
                    ));
                    filters.extend(RequestedPathWidget::build_filters(
                        parsed_stats,
                        &requested_path_state,
                    ));

                    self.filters = filters;

                    self.apply_filters();
                } else {
                    self.filtered = FilteredData::Loading;
                }

                rebuild_filters = false;
            }

            let ow = if let Some(w) = overview_widget.as_ref() {
                w
            } else {
                let filtered_events = filtered!(self).map(|fe| fe.0);
                let filtered_stats = filtered!(self).map(|fe| fe.1);
                let w = OverviewWidget::new(
                    &self.warnings,
                    filtered_events,
                    self.parsed_stats.as_ref(),
                    filtered_stats,
                );
                overview_widget = Some(w);
                overview_widget.as_ref().expect("just assigned")
            };

            terminal.draw(|frame| {
                frame.render_stateful_widget_ref(
                    ow,
                    frame.area(),
                    &mut (
                        self,
                        &mut warnings_widget_state,
                        &mut events_widget_state,
                        &mut source_ip_state,
                        &mut destination_ip_state,
                        &mut rule_id_state,
                        &mut rule_severity_state,
                        &mut http_status_state,
                        &mut http_method_state,
                        &mut requested_host_state,
                        &mut requested_path_state,
                    ),
                );

                if let Some(w) = event_popup_widget.as_ref() {
                    frame.render_widget_ref(w, frame.area());
                }

                if let Some(w) = custom_input_popup_widget.as_ref() {
                    frame.render_stateful_widget_ref(
                        w,
                        frame.area(),
                        &mut custom_input_popup_state,
                    );
                    frame.set_cursor_position(custom_input_popup_state.cursor_pos);
                }

                if let Some(w) = search_popup_widget.as_ref() {
                    frame.render_stateful_widget_ref(w, frame.area(), &mut search_popup_state);
                    frame.set_cursor_position(search_popup_state.cursor_pos);
                }

                if self.quit_popup {
                    frame.render_widget_ref(&quit_popup_widget, frame.area());
                }
            })?;

            /* Read the next event from the input thread */
            let event = event_rx
                .recv()
                .expect("input thread should not die before TUI thread");

            match event {
                AppEvent::Term(termevent) => {
                    if let Event::Key(key) = termevent {
                        if key.kind == KeyEventKind::Press {
                            if self.quit_popup {
                                match key.code {
                                    KeyCode::Char('y' | 'Y') => return Ok(Succession::Quit),
                                    KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                                        self.quit_popup = false;
                                    }
                                    KeyCode::Char('c')
                                        if key.modifiers == KeyModifiers::CONTROL =>
                                    {
                                        return Ok(Succession::Quit);
                                    }
                                    _ => {}
                                }

                                continue;
                            }

                            if let Some(_widget) = custom_input_popup_widget.as_ref() {
                                match key.code {
                                    KeyCode::Char('c')
                                        if key.modifiers == KeyModifiers::CONTROL =>
                                    {
                                        return Ok(Succession::Quit);
                                    }
                                    KeyCode::Esc => {
                                        custom_input_popup_widget = None;
                                        custom_input_popup_state.reset();
                                    }
                                    KeyCode::Enter => {
                                        let input = &custom_input_popup_state.input;

                                        // TODO: minimize boilerplate
                                        match self.active_panel {
                                            ActivePanel::None
                                            | ActivePanel::EventsPanel
                                            | ActivePanel::WarningsPanel => unreachable!(),
                                            ActivePanel::SourceIp => {
                                                let ip: IpDetail = match input.parse() {
                                                    Ok(ip) => ip,
                                                    Err(err) => {
                                                        custom_input_popup_state.invalid_input =
                                                            Some((input.clone(), err.into()));
                                                        continue;
                                                    }
                                                };
                                                source_ip_state.custom.push(ip);
                                            }
                                            ActivePanel::DestinationIp => {
                                                let ip: IpDetail = match input.parse() {
                                                    Ok(ip) => ip,
                                                    Err(err) => {
                                                        custom_input_popup_state.invalid_input =
                                                            Some((input.clone(), err.into()));
                                                        continue;
                                                    }
                                                };
                                                destination_ip_state.custom.push(ip);
                                            }
                                            ActivePanel::RuleId => {
                                                let id: RuleId = match input.parse() {
                                                    Ok(id) => id,
                                                    Err(err) => {
                                                        custom_input_popup_state.invalid_input =
                                                            Some((input.clone(), err.into()));
                                                        continue;
                                                    }
                                                };
                                                rule_id_state.custom.push(id);
                                            }
                                            ActivePanel::RuleSeverity => {
                                                let sev: RuleSeverity = match input.parse() {
                                                    Ok(sev) => sev,
                                                    Err(err) => {
                                                        custom_input_popup_state.invalid_input =
                                                            Some((input.clone(), err.into()));
                                                        continue;
                                                    }
                                                };
                                                rule_severity_state
                                                    .custom
                                                    .push(DisplayRuleSeverity::Some(sev));
                                            }
                                            ActivePanel::HttpStatus => {
                                                let code: HttpStatusCode = match input.parse() {
                                                    Ok(code) => code,
                                                    Err(err) => {
                                                        custom_input_popup_state.invalid_input =
                                                            Some((input.clone(), err.into()));
                                                        continue;
                                                    }
                                                };
                                                http_status_state.custom.push(code);
                                            }
                                            ActivePanel::HttpMethod => {
                                                http_method_state.custom.push(input.clone());
                                            }
                                            ActivePanel::RequestedHost => {
                                                requested_host_state.custom.push(input.clone());
                                            }
                                            ActivePanel::RequestedPath => {
                                                requested_path_state.custom.push(input.clone());
                                            }
                                        }

                                        custom_input_popup_widget = None;
                                        custom_input_popup_state.reset();

                                        rebuild_filters = true;
                                    }
                                    KeyCode::Tab => {
                                        custom_input_popup_state.tab();
                                    }
                                    KeyCode::Char(to_insert) => {
                                        custom_input_popup_state.enter_char(to_insert);
                                    }
                                    KeyCode::Backspace => {
                                        custom_input_popup_state.delete_char_left();
                                    }
                                    KeyCode::Delete => custom_input_popup_state.delete_char_right(),
                                    KeyCode::Left => custom_input_popup_state.move_cursor_left(),
                                    KeyCode::Right => custom_input_popup_state.move_cursor_right(),
                                    KeyCode::Up => {
                                        custom_input_popup_state.previous_suggestion();
                                    }
                                    KeyCode::Down => {
                                        custom_input_popup_state.next_suggestion();
                                    }
                                    _ => {}
                                }

                                continue;
                            }

                            if search_popup_widget.is_some() {
                                match key.code {
                                    KeyCode::Char('c')
                                        if key.modifiers == KeyModifiers::CONTROL =>
                                    {
                                        return Ok(Succession::Quit);
                                    }
                                    KeyCode::Esc => {
                                        search_popup_widget = None;
                                        search_popup_state.reset();
                                    }
                                    KeyCode::Char(to_insert) => {
                                        search_popup_state.enter_char(to_insert);
                                    }
                                    KeyCode::Backspace => {
                                        search_popup_state.delete_char_left();
                                    }
                                    KeyCode::Delete => search_popup_state.delete_char_right(),
                                    KeyCode::Left => search_popup_state.move_cursor_left(),
                                    KeyCode::Right => search_popup_state.move_cursor_right(),
                                    KeyCode::Up => {
                                        search_popup_state.select_previous();
                                    }
                                    KeyCode::Down => {
                                        search_popup_state.select_next();
                                    }
                                    KeyCode::PageUp => {
                                        search_popup_state.scroll_up_by(SCROLL_COUNT);
                                    }
                                    KeyCode::PageDown => {
                                        search_popup_state.scroll_down_by(SCROLL_COUNT);
                                    }
                                    KeyCode::Home => search_popup_state.select_first(),
                                    KeyCode::End => search_popup_state.select_last(),
                                    KeyCode::Enter => {
                                        if let Some(input) = &search_popup_state.selected {
                                            // TODO: minimize boilerplate
                                            match self.active_panel {
                                                ActivePanel::None
                                                | ActivePanel::EventsPanel
                                                | ActivePanel::WarningsPanel => unreachable!(),
                                                ActivePanel::SourceIp => {
                                                    let ip: IpDetail = input
                                                        .parse()
                                                        .expect("input should be valid");
                                                    source_ip_state.custom.push(ip);
                                                }
                                                ActivePanel::DestinationIp => {
                                                    let ip: IpDetail = input
                                                        .parse()
                                                        .expect("input should be valid");
                                                    destination_ip_state.custom.push(ip);
                                                }
                                                ActivePanel::RuleId => {
                                                    let id: RuleId = input
                                                        .parse()
                                                        .expect("input should be valid");
                                                    rule_id_state.custom.push(id);
                                                }
                                                ActivePanel::RuleSeverity => {
                                                    let sev: RuleSeverity = input
                                                        .parse()
                                                        .expect("input should be valid");
                                                    rule_severity_state
                                                        .custom
                                                        .push(DisplayRuleSeverity::Some(sev));
                                                }
                                                ActivePanel::HttpStatus => {
                                                    let code: HttpStatusCode = input
                                                        .parse()
                                                        .expect("input should be valid");
                                                    http_status_state.custom.push(code);
                                                }
                                                ActivePanel::HttpMethod => {
                                                    http_method_state.custom.push(input.clone());
                                                }
                                                ActivePanel::RequestedHost => {
                                                    requested_host_state.custom.push(input.clone());
                                                }
                                                ActivePanel::RequestedPath => {
                                                    requested_path_state.custom.push(input.clone());
                                                }
                                            }

                                            search_popup_widget = None;
                                            search_popup_state.reset();

                                            rebuild_filters = true;
                                        }
                                    }
                                    _ => {}
                                }

                                continue;
                            }

                            if event_popup_widget.is_some() {
                                let filtered_events = filtered!(self)
                                .expect("when the event popup is active the filtered events must be loaded")
                                .0;

                                let total_filtered_events = filtered_events.len();

                                let index = events_widget_state.selected().unwrap_or(0);

                                let index = match key.code {
                                    KeyCode::Char('q' | 'Q') => {
                                        self.quit_popup = true;
                                        continue;
                                    }
                                    KeyCode::Char('c')
                                        if key.modifiers == KeyModifiers::CONTROL =>
                                    {
                                        return Ok(Succession::Quit);
                                    }
                                    KeyCode::Esc | KeyCode::Char('p') => {
                                        event_popup_widget = None;
                                        continue;
                                    }
                                    KeyCode::Up => index.saturating_sub(1),
                                    KeyCode::Down => index
                                        .saturating_add(1)
                                        .min(total_filtered_events.saturating_sub(1)),
                                    KeyCode::PageUp => index
                                        .saturating_sub(SCROLL_COUNT as usize)
                                        .min(total_filtered_events.saturating_sub(1)),
                                    KeyCode::PageDown => index
                                        .saturating_add(SCROLL_COUNT as usize)
                                        .min(total_filtered_events.saturating_sub(1)),
                                    KeyCode::Home => 0,
                                    KeyCode::End => total_filtered_events.saturating_sub(1),
                                    _ => continue,
                                };

                                //if self.active_panel == ActivePanel::EventsPanel {
                                events_widget_state.select(Some(index));
                                //}

                                let event =
                                    filtered_events.get(index).expect("index should be valid");
                                event_popup_widget = Some(EventPopupWidget::new(
                                    event,
                                    index,
                                    total_filtered_events,
                                ));

                                continue;
                            }

                            if self.active_panel == ActivePanel::None
                                && let KeyCode::Char(c) = key.code
                                && let Some(panel) = ActivePanel::from_id(c)
                            {
                                self.active_panel = panel;
                                continue;
                            }

                            match key.code {
                                KeyCode::Char('q' | 'Q') => {
                                    self.quit_popup = true;
                                    continue;
                                }
                                KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                                    return Ok(Succession::Quit);
                                }
                                KeyCode::Char('e') => {
                                    self.show_events = self.show_events.next();
                                }
                                KeyCode::Char('E') => {
                                    self.show_events = self.show_events.previous();
                                }
                                KeyCode::Char('w') => {
                                    self.show_warnings = !self.show_warnings;
                                    if self.active_panel == ActivePanel::WarningsPanel
                                        && !self.show_warnings
                                    {
                                        self.active_panel = ActivePanel::None;
                                        continue;
                                    }
                                }
                                KeyCode::Char('p')
                                    if self.active_panel != ActivePanel::EventsPanel =>
                                {
                                    assert!(event_popup_widget.is_none());
                                    if let Some((event, total_events)) = filtered!(self)
                                        .and_then(|fe| fe.0.first().map(|e| (e, fe.0.len())))
                                    {
                                        event_popup_widget =
                                            Some(EventPopupWidget::new(event, 0, total_events));
                                        if events_widget_state.selected().is_none() {
                                            events_widget_state.select_first();
                                        }
                                    }

                                    continue;
                                }
                                KeyCode::Char('R') => {
                                    if self.filters.is_empty() {
                                        /* nothing to reset */
                                        continue;
                                    }

                                    source_ip_state.reset();
                                    destination_ip_state.reset();
                                    rule_id_state.reset();
                                    rule_severity_state.reset();
                                    http_status_state.reset();
                                    http_method_state.reset();
                                    requested_host_state.reset();
                                    requested_path_state.reset();

                                    event_popup_widget = None;
                                    overview_widget = None;

                                    self.filters = Vec::new();
                                    self.apply_filters();
                                }
                                KeyCode::Tab => {
                                    self.active_panel = self.active_panel.next();
                                    if self.active_panel == ActivePanel::WarningsPanel
                                        && !self.show_warnings
                                    {
                                        self.active_panel = self.active_panel.next();
                                    }
                                }
                                KeyCode::BackTab => {
                                    self.active_panel = self.active_panel.previous();
                                    if self.active_panel == ActivePanel::WarningsPanel
                                        && !self.show_warnings
                                    {
                                        self.active_panel = self.active_panel.previous();
                                    }
                                }
                                _ => {}
                            }
                        }

                        if self.active_panel == ActivePanel::EventsPanel
                            && self.show_events == EventVisibility::Hidden
                        {
                            self.show_events = EventVisibility::Partial;
                        }

                        let action = match self.active_panel {
                            ActivePanel::None => Action::None,
                            ActivePanel::SourceIp => source_ip_state.handle_keyevent(key),
                            ActivePanel::DestinationIp => destination_ip_state.handle_keyevent(key),
                            ActivePanel::RuleId => rule_id_state.handle_keyevent(key),
                            ActivePanel::RuleSeverity => rule_severity_state.handle_keyevent(key),
                            ActivePanel::HttpStatus => http_status_state.handle_keyevent(key),
                            ActivePanel::HttpMethod => http_method_state.handle_keyevent(key),
                            ActivePanel::RequestedHost => requested_host_state.handle_keyevent(key),
                            ActivePanel::RequestedPath => requested_path_state.handle_keyevent(key),
                            ActivePanel::WarningsPanel => {
                                WarningsWidget::handle_keyevent(key, &mut warnings_widget_state)
                            }
                            ActivePanel::EventsPanel => {
                                EventsWidget::handle_keyevent(key, &mut events_widget_state)
                            }
                        };

                        match action {
                            Action::None => {}
                            Action::Unselect => {
                                self.active_panel = ActivePanel::None;
                            }
                            Action::FilterUpdate => {
                                rebuild_filters = true;
                            }
                            Action::ShowEventDetails(index) => {
                                let filtered_events =
                                    filtered!(self).expect("events should be filtered").0;
                                let event =
                                    filtered_events.get(index).expect("index should be valid");
                                let total_events = filtered_events.len();
                                event_popup_widget =
                                    Some(EventPopupWidget::new(event, index, total_events));
                            }
                            Action::AddFilter(kind, index) => {
                                event_popup_widget = None;
                                overview_widget = None;

                                let event = filtered!(self).expect("the panels should emit this action only if filtered events are loaded").0.get(index).expect("panels should return valid indices");

                                let filter = match kind {
                                    AddFilterKind::SourceIpMatch => {
                                        event.source_ip.map(|source_ip| {
                                            EventFilter::SourceIpMatch(SourceIpMatch {
                                                ipnets: vec![IpDetail::Single(source_ip)],
                                            })
                                        })
                                    }
                                    AddFilterKind::SourceIpExclude => {
                                        event.source_ip.map(|source_ip| {
                                            EventFilter::SourceIpExclude(SourceIpExclude {
                                                ipnet: IpDetail::Single(source_ip),
                                            })
                                        })
                                    }
                                };

                                if let Some(filter) = filter {
                                    if let Some(index) =
                                        self.filters.iter().position(|f| *f == filter)
                                    {
                                        self.filters.remove(index);
                                    } else {
                                        self.filters.push(filter);
                                    }

                                    self.apply_filters();
                                }
                            }
                            Action::CustomInput | Action::Search => {
                                // TODO: minimize boilerplate
                                let (existing, name) = match self.active_panel {
                                    ActivePanel::None
                                    | ActivePanel::EventsPanel
                                    | ActivePanel::WarningsPanel => unreachable!(),
                                    ActivePanel::SourceIp => (
                                        self.parsed_stats.as_ref().map_or(Vec::new(), |ps| {
                                            SourceIpWidget::collect_entries(ps)
                                        }),
                                        SourceIpWidget::NAME,
                                    ),
                                    ActivePanel::DestinationIp => (
                                        self.parsed_stats.as_ref().map_or(Vec::new(), |ps| {
                                            DestinationIpWidget::collect_entries(ps)
                                        }),
                                        DestinationIpWidget::NAME,
                                    ),
                                    ActivePanel::RuleId => (
                                        self.parsed_stats.as_ref().map_or(Vec::new(), |ps| {
                                            RuleIdWidget::collect_entries(ps)
                                        }),
                                        RuleIdWidget::NAME,
                                    ),
                                    ActivePanel::RuleSeverity => (
                                        self.parsed_stats.as_ref().map_or(Vec::new(), |ps| {
                                            RuleSeverityWidget::collect_entries(ps)
                                        }),
                                        RuleSeverityWidget::NAME,
                                    ),
                                    ActivePanel::HttpStatus => (
                                        self.parsed_stats.as_ref().map_or(Vec::new(), |ps| {
                                            HttpStatusWidget::collect_entries(ps)
                                        }),
                                        HttpStatusWidget::NAME,
                                    ),
                                    ActivePanel::HttpMethod => (
                                        self.parsed_stats.as_ref().map_or(Vec::new(), |ps| {
                                            HttpMethodWidget::collect_entries(ps)
                                        }),
                                        HttpMethodWidget::NAME,
                                    ),
                                    ActivePanel::RequestedHost => (
                                        self.parsed_stats.as_ref().map_or(Vec::new(), |ps| {
                                            RequestedHostWidget::collect_entries(ps)
                                        }),
                                        RequestedHostWidget::NAME,
                                    ),
                                    ActivePanel::RequestedPath => (
                                        self.parsed_stats.as_ref().map_or(Vec::new(), |ps| {
                                            RequestedPathWidget::collect_entries(ps)
                                        }),
                                        RequestedPathWidget::NAME,
                                    ),
                                };

                                if matches!(action, Action::CustomInput) {
                                    custom_input_popup_state.existing = existing;
                                    custom_input_popup_widget =
                                        Some(CustomInputPopupWidget::new(name));
                                } else {
                                    assert!(matches!(action, Action::Search));
                                    search_popup_state.existing = existing;
                                    search_popup_widget = Some(SearchPopupWidget::new(name));
                                }
                            }
                        }
                    }
                }
                AppEvent::ProcessedFile(_) => unreachable!(),
                AppEvent::CalculatedSummary(stats) => {
                    overview_widget = None;
                    self.parsed_stats = Some(stats);
                }
                AppEvent::ProcessedFilters(seqno, filtered_events, filtered_stats) => {
                    /* apply only live sequence numbers */
                    if self.seqno.0 == seqno {
                        event_popup_widget = None;
                        overview_widget = None;
                        self.filtered = FilteredData::Filtered(filtered_events, filtered_stats);
                    }
                }
            }
        }
    }

    fn apply_filters(&mut self) {
        self.seqno += 1;

        if self.filters.is_empty() {
            self.filtered = FilteredData::Unfiltered;
        } else {
            self.filtered = FilteredData::Loading;
            self.task_tx
                .send(AppTask::ProcessFilters(
                    self.seqno.0,
                    Arc::clone(&self.parsed_events),
                    self.filters.clone(),
                    Arc::clone(&self.rule_descriptions),
                    Arc::clone(&self.http_descriptions),
                ))
                .expect("task thread should not die before TUI thread");
        }
    }
}

struct OverviewWidget<'a> {
    warnings: WarningsWidget<'a>,
    events: EventsWidget<'a>,
    source_ip: SourceIpWidget,
    destination_ip: DestinationIpWidget,
    rule_id: RuleIdWidget,
    rule_severity: RuleSeverityWidget,
    http_status: HttpStatusWidget,
    http_method: HttpMethodWidget,
    requested_host: RequestedHostWidget,
    requested_path: RequestedPathWidget,
}

impl<'a> OverviewWidget<'a> {
    #[must_use]
    fn new(
        warnings: &'a [String],
        events: Option<&'a [ModSecurityEvent]>,
        parsed_stats: Option<&'a Statistics>,
        filtered_stats: Option<&'a Statistics>,
    ) -> Self {
        Self {
            warnings: WarningsWidget::new(warnings),
            events: EventsWidget::new(events, parsed_stats, filtered_stats),
            source_ip: SourceIpWidget {},
            destination_ip: DestinationIpWidget {},
            rule_id: RuleIdWidget {},
            rule_severity: RuleSeverityWidget {},
            http_status: HttpStatusWidget {},
            http_method: HttpMethodWidget {},
            requested_host: RequestedHostWidget {},
            requested_path: RequestedPathWidget {},
        }
    }
}

impl<'a> StatefulWidgetRef for &'a OverviewWidget<'a> {
    type State = (
        &'a OverviewScreen,
        &'a mut ListState,
        &'a mut ListState,
        &'a mut DetailState<SourceIpWidget>,
        &'a mut DetailState<DestinationIpWidget>,
        &'a mut DetailState<RuleIdWidget>,
        &'a mut DetailState<RuleSeverityWidget>,
        &'a mut DetailState<HttpStatusWidget>,
        &'a mut DetailState<HttpMethodWidget>,
        &'a mut DetailState<RequestedHostWidget>,
        &'a mut DetailState<RequestedPathWidget>,
    );

    fn render_ref(&self, area: Rect, buf: &mut Buffer, state: &mut Self::State)
    where
        Self: Sized,
    {
        let (
            screen,
            warnings_state,
            events_state,
            source_ip_state,
            destination_ip_state,
            rule_id_state,
            rule_severity_state,
            http_status_state,
            http_method_state,
            requetsed_host_state,
            requested_path_state,
        ) = state;

        let inner_area = {
            let title = Line::from(" ModSecLog :: Overview ")
                .centered()
                .style(PROGRAM_TITLE_STYLE);
            let mut main_block = Block::bordered().border_set(border::PLAIN).title(title);

            if !screen.quit_popup {
                let instructions = Line::default()
                    .spans([
                        Span::raw(" Hide/Show events "),
                        Span::styled("<e> ", KEY_HINT_STYLE),
                        Span::raw(" Hide/Show warnings "),
                        Span::styled("<w> ", KEY_HINT_STYLE),
                        Span::raw(" Select Details "),
                        Span::styled("<tab> ", KEY_HINT_STYLE),
                        Span::styled(
                            " Reset Filter ",
                            if screen.filters.is_empty() {
                                Style::new().fg(DarkGray)
                            } else {
                                Style::default()
                            },
                        ),
                        Span::styled("<R> ", KEY_HINT_STYLE),
                        Span::raw(" Quit "),
                        Span::styled("<q> ", KEY_HINT_STYLE),
                    ])
                    .centered();
                main_block = main_block.title_bottom(instructions);
            }

            if screen.show_events == EventVisibility::Hidden {
                let events_hint = Line::from(format!(" Events ({}) ", screen.parsed_events.len()))
                    .white()
                    .left_aligned();
                main_block = main_block.title_bottom(events_hint);
            }

            if !screen.show_warnings {
                let warnings_hint = Line::from(format!(" Warnings ({}) ", screen.warnings.len()))
                    .white()
                    .left_aligned();
                main_block = main_block.title_bottom(warnings_hint);
            }

            let ia = main_block.inner(area);

            main_block.render(area, buf);

            ia
        };

        let percentages = match (&screen.show_events, screen.show_warnings) {
            (EventVisibility::Partial, true) => [60, 20, 20],
            (EventVisibility::Hidden, false) => [100, 0, 0],
            (EventVisibility::Partial, false) => [70, 30, 0],
            (EventVisibility::Hidden, true) => [80, 0, 20],
            (EventVisibility::Full, true) => [0, 80, 20],
            (EventVisibility::Full, false) => [0, 100, 0],
        };
        let [details_area, events_area, warnings_area] =
            Layout::vertical(Constraint::from_percentages(percentages)).areas(inner_area);

        let [details_first_area, details_second_area, details_third_area] =
            Layout::vertical(Constraint::from_fills([1, 1, 1])).areas(details_area);

        let [
            source_ip_area,
            destination_ip_area,
            http_status_area,
            http_method_area,
        ] = Layout::horizontal(Constraint::from_fills([1, 1, 1, 1])).areas(details_first_area);

        let filtered_stats = filtered!(screen).map(|f| f.1);

        self.source_ip.render(
            source_ip_area,
            buf,
            screen.active_panel,
            screen.parsed_stats.as_ref(),
            filtered_stats,
            source_ip_state,
        );

        self.destination_ip.render(
            destination_ip_area,
            buf,
            screen.active_panel,
            screen.parsed_stats.as_ref(),
            filtered_stats,
            destination_ip_state,
        );

        self.http_status.render(
            http_status_area,
            buf,
            screen.active_panel,
            screen.parsed_stats.as_ref(),
            filtered_stats,
            http_status_state,
        );

        self.http_method.render(
            http_method_area,
            buf,
            screen.active_panel,
            screen.parsed_stats.as_ref(),
            filtered_stats,
            http_method_state,
        );

        let [rule_id_area, rule_severity_area] =
            Layout::horizontal(Constraint::from_fills([1, 1])).areas(details_second_area);

        self.rule_id.render(
            rule_id_area,
            buf,
            screen.active_panel,
            screen.parsed_stats.as_ref(),
            filtered_stats,
            rule_id_state,
        );

        self.rule_severity.render(
            rule_severity_area,
            buf,
            screen.active_panel,
            screen.parsed_stats.as_ref(),
            filtered_stats,
            rule_severity_state,
        );

        let [requested_host_area, requested_path_area] =
            Layout::horizontal(Constraint::from_fills([1, 1])).areas(details_third_area);

        self.requested_host.render(
            requested_host_area,
            buf,
            screen.active_panel,
            screen.parsed_stats.as_ref(),
            filtered_stats,
            requetsed_host_state,
        );

        self.requested_path.render(
            requested_path_area,
            buf,
            screen.active_panel,
            screen.parsed_stats.as_ref(),
            filtered_stats,
            requested_path_state,
        );

        let w: &EventsWidget<'_> = &self.events;
        w.render_ref(
            events_area,
            buf,
            &mut (
                events_state,
                screen.active_panel,
                !screen.filters.is_empty(),
            ),
        );

        let w: &WarningsWidget<'_> = &self.warnings;
        w.render_ref(
            warnings_area,
            buf,
            &mut (warnings_state, screen.active_panel),
        );
    }
}

struct QuitPopupWidget<'a> {
    block: Block<'a>,
    paragraph: Paragraph<'a>,
}

impl QuitPopupWidget<'_> {
    #[must_use]
    fn new() -> Self {
        let title = Line::from(" ModSecLog :: Quitting ")
            .centered()
            .style(HEADER_ACTIVE_STYLE);
        let instructions = Line::default()
            .spans([
                Span::raw(" Yes "),
                Span::styled("<y> ", KEY_HINT_STYLE),
                Span::raw(" No "),
                Span::styled("<n> ", KEY_HINT_STYLE),
            ])
            .centered();
        let block = Block::bordered()
            .title(title)
            .title_bottom(instructions)
            .border_type(BorderType::QuadrantOutside);
        let paragraph = Paragraph::new("Do you want to quit ModSecLog?")
            .wrap(Wrap { trim: true })
            .centered();

        Self { block, paragraph }
    }
}

impl WidgetRef for &QuitPopupWidget<'_> {
    fn render_ref(&self, area: Rect, buf: &mut Buffer) {
        let popup_area = popup_area_absolute(area, 40, 10);
        Clear.render(popup_area, buf);

        let [_top_area, text_area] =
            Layout::vertical([Constraint::Length(4), Constraint::Fill(1)]).areas(popup_area);

        let w = &self.block;
        w.render_ref(popup_area, buf);

        let w = &self.paragraph;
        w.render_ref(text_area, buf);
    }
}

struct CustomInputPopupWidget<'a> {
    block: Block<'a>,
    paragraph: Paragraph<'a>,
}

impl CustomInputPopupWidget<'_> {
    #[must_use]
    fn new(kind: &'static str) -> Self {
        let title = Line::from(format!(" Add Custom {kind} Filter "))
            .centered()
            .style(HEADER_ACTIVE_STYLE);
        let instructions = Line::default()
            .spans([
                Span::raw(" Add "),
                Span::styled("<enter> ", KEY_HINT_STYLE),
                Span::raw(" Discard "),
                Span::styled("<esc> ", KEY_HINT_STYLE),
            ])
            .centered();
        let block = Block::bordered()
            .border_set(border::THICK)
            .title(title)
            .title_bottom(instructions);
        let paragraph = Paragraph::new(format!(
            "Enter the {} to filter for:",
            kind.to_ascii_lowercase()
        ))
        .wrap(Wrap { trim: true })
        .centered();

        Self { block, paragraph }
    }
}

enum InputError {
    AddrParse(ipnet::AddrParseError),
    IntParse(ParseIntError),
    StaticMsg(&'static str),
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddrParse(err) => write!(f, "{err}"),
            Self::IntParse(err) => write!(f, "{err}"),
            Self::StaticMsg(err) => write!(f, "{err}"),
        }
    }
}

impl From<ParseIntError> for InputError {
    fn from(value: ParseIntError) -> Self {
        Self::IntParse(value)
    }
}

impl From<&'static str> for InputError {
    fn from(value: &'static str) -> Self {
        Self::StaticMsg(value)
    }
}

impl From<ipnet::AddrParseError> for InputError {
    fn from(value: ipnet::AddrParseError) -> Self {
        Self::AddrParse(value)
    }
}

struct CustomInputPopupState {
    input: String,
    input_pos: Saturating<usize>,
    cursor_pos: Position,
    invalid_input: Option<(String, InputError)>,
    existing: Vec<String>,
    suggestion: Option<String>,
    suggestion_skip: Saturating<usize>,
}

impl CustomInputPopupState {
    #[must_use]
    const fn new(existing: Vec<String>) -> Self {
        Self {
            input: String::new(),
            input_pos: Saturating(0),
            cursor_pos: Position::new(0, 0),
            invalid_input: None,
            existing,
            suggestion: None,
            suggestion_skip: Saturating(0),
        }
    }

    fn reset(&mut self) {
        self.input.clear();
        self.input_pos = Saturating(0);
        self.invalid_input = None;
        self.suggestion = None;
        self.existing.clear();
        self.suggestion_skip = Saturating(0);
    }

    fn move_cursor_left(&mut self) {
        self.input_pos -= 1;
    }

    fn move_cursor_right(&mut self) {
        self.input_pos =
            (self.input_pos + Saturating(1)).min(Saturating(self.input.chars().count()));
    }

    /// Returns the byte index based on the character position.
    ///
    /// Since each character in a string can be contain multiple bytes, it's necessary to calculate
    /// the byte index based on the index of the character.
    #[must_use]
    fn byte_index(&self) -> usize {
        self.input
            .char_indices()
            .map(|(i, _)| i)
            .nth(self.input_pos.0)
            .unwrap_or(self.input.len())
    }

    fn enter_char(&mut self, new_char: char) {
        let index = self.byte_index();
        self.input.insert(index, new_char);
        self.move_cursor_right();

        self.set_suggestion(false);
    }

    fn set_suggestion(&mut self, force: bool) {
        if self.input.is_empty() {
            self.suggestion = match self.suggestion {
                Some(_) => None,
                None => self.existing.first().cloned(),
            };
        } else if force
            || !self
                .suggestion
                .as_ref()
                .is_some_and(|s| s.starts_with(&self.input))
        {
            let mut skip = 0;
            let mut iter = self.existing.iter().filter(|e| e.starts_with(&self.input));
            let mut item = iter.next();
            loop {
                if skip == self.suggestion_skip.0 {
                    self.suggestion = item.cloned();
                    break;
                }

                if let Some(i) = iter.next() {
                    item = Some(i);
                } else {
                    self.suggestion = item.cloned();
                    self.suggestion_skip = Saturating(skip);
                    break;
                }

                skip += 1;
            }
        }
    }

    fn take_suggestion(&mut self) {
        if let Some(sug) = self.suggestion.take() {
            self.input = sug;
            self.input_pos = Saturating(self.input.chars().count());
        }
    }

    fn tab(&mut self) {
        if self.input.is_empty() {
            self.set_suggestion(false);
        } else {
            self.take_suggestion();
        }
    }

    fn previous_suggestion(&mut self) {
        self.suggestion_skip -= 1;
        self.set_suggestion(true);
    }

    fn next_suggestion(&mut self) {
        self.suggestion_skip += 1;
        self.set_suggestion(true);
    }

    fn delete_char_left(&mut self) {
        let is_not_cursor_leftmost = self.input_pos.0 != 0;
        if is_not_cursor_leftmost {
            // Method "remove" is not used on the saved text for deleting the selected char.
            // Reason: Using remove on String works on bytes instead of the chars.
            // Using remove would require special care because of char boundaries.

            let current_index = self.input_pos.0;
            let from_left_to_current_index = current_index - 1;

            // Getting all characters before the selected character.
            let before_char_to_delete = self.input.chars().take(from_left_to_current_index);
            // Getting all characters after selected character.
            let after_char_to_delete = self.input.chars().skip(current_index);

            // Put all characters together except the selected one.
            // By leaving the selected one out, it is forgotten and therefore deleted.
            self.input = before_char_to_delete.chain(after_char_to_delete).collect();
            self.move_cursor_left();

            self.set_suggestion(false);
        }
    }

    fn delete_char_right(&mut self) {
        let is_not_cursor_rightmost = self.input_pos.0 != self.input.chars().count();
        if is_not_cursor_rightmost {
            // Method "remove" is not used on the saved text for deleting the selected char.
            // Reason: Using remove on String works on bytes instead of the chars.
            // Using remove would require special care because of char boundaries.

            let current_index = self.input_pos.0;
            let from_right_to_current_index = current_index + 1;

            // Getting all characters before the selected character.
            let before_char_to_delete = self.input.chars().take(current_index);
            // Getting all characters after selected character.
            let after_char_to_delete = self.input.chars().skip(from_right_to_current_index);

            // Put all characters together except the selected one.
            // By leaving the selected one out, it is forgotten and therefore deleted.
            self.input = before_char_to_delete.chain(after_char_to_delete).collect();

            self.set_suggestion(false);
        }
    }
}

impl StatefulWidgetRef for &CustomInputPopupWidget<'_> {
    type State = CustomInputPopupState;

    fn render_ref(&self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let popup_area = popup_area_absolute(area, 45, 15);
        Clear.render(popup_area, buf);

        let inner_area = self.block.inner(popup_area);

        let [_top_area, text_area, input_area, invalid_area, _bottom_area] = Layout::vertical([
            Constraint::Length(4),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Fill(1),
        ])
        .areas(inner_area);

        let w = &self.block;
        w.render_ref(popup_area, buf);

        let w = &self.paragraph;
        w.render_ref(text_area, buf);

        if let Some((input, err)) = state.invalid_input.as_ref() {
            let spans = [
                Span::from("! ").red().bold(),
                Span::raw("Failed to parse "),
                input.as_str().not_bold().italic().yellow(),
                Span::raw(":"),
                Span::from(" !\n").red().bold(),
            ];
            let line1 = Line::default().spans(spans);
            let line2 = Line::from(err.to_string());

            let paragraph = Paragraph::new(vec![line1, line2])
                .wrap(Wrap { trim: true })
                .centered();

            paragraph.render(invalid_area, buf);
        }

        let block = Block::bordered().border_set(border::PLAIN);

        let mut input_line = Line::from(state.input.as_str());

        #[expect(clippy::string_slice, reason = "suggestion matches state input")]
        if let Some(sug) = &state.suggestion {
            input_line.push_span(Span::from(&sug[state.input.len()..]).style(HIDDEN_STYLE));
        }

        let input = Paragraph::new(Text::from(input_line)).block(block);

        input.render(input_area, buf);

        #[expect(
            clippy::cast_possible_truncation,
            reason = "input should not exceed u16"
        )]
        {
            state.cursor_pos = Position::new(
                input_area.x + state.input_pos.0 as u16 + 1,
                input_area.y + 1,
            );
        }
    }
}

struct SearchPopupWidget {
    title: String,
    hint: String,
}

impl SearchPopupWidget {
    #[must_use]
    fn new(kind: &'static str) -> Self {
        let title = format!(" Search {kind} ");

        let hint = format!("the {} to search for", kind.to_ascii_lowercase());

        Self { title, hint }
    }
}

struct SearchPopupState {
    input: String,
    input_pos: Saturating<usize>,
    cursor_pos: Position,
    existing: Vec<String>,
    list_state: ListState,
    selected: Option<String>,
}

impl SearchPopupState {
    #[must_use]
    fn new(existing: Vec<String>) -> Self {
        Self {
            input: String::new(),
            input_pos: Saturating(0),
            cursor_pos: Position::default(),
            existing,
            list_state: ListState::default(),
            selected: None,
        }
    }

    fn reset(&mut self) {
        self.input.clear();
        self.input_pos = Saturating(0);
        self.existing.clear();
        self.list_state.select(None);
        self.selected = None;
    }

    fn move_cursor_left(&mut self) {
        self.input_pos -= 1;
    }

    fn move_cursor_right(&mut self) {
        self.input_pos =
            (self.input_pos + Saturating(1)).min(Saturating(self.input.chars().count()));
    }

    /// Returns the byte index based on the character position.
    ///
    /// Since each character in a string can be contain multiple bytes, it's necessary to calculate
    /// the byte index based on the index of the character.
    #[must_use]
    fn byte_index(&self) -> usize {
        self.input
            .char_indices()
            .map(|(i, _)| i)
            .nth(self.input_pos.0)
            .unwrap_or(self.input.len())
    }

    fn enter_char(&mut self, new_char: char) {
        let index = self.byte_index();
        self.input.insert(index, new_char);
        self.move_cursor_right();
    }

    fn delete_char_left(&mut self) {
        let is_not_cursor_leftmost = self.input_pos.0 != 0;
        if is_not_cursor_leftmost {
            // Method "remove" is not used on the saved text for deleting the selected char.
            // Reason: Using remove on String works on bytes instead of the chars.
            // Using remove would require special care because of char boundaries.

            let current_index = self.input_pos.0;
            let from_left_to_current_index = current_index - 1;

            // Getting all characters before the selected character.
            let before_char_to_delete = self.input.chars().take(from_left_to_current_index);
            // Getting all characters after selected character.
            let after_char_to_delete = self.input.chars().skip(current_index);

            // Put all characters together except the selected one.
            // By leaving the selected one out, it is forgotten and therefore deleted.
            self.input = before_char_to_delete.chain(after_char_to_delete).collect();
            self.move_cursor_left();
        }
    }

    fn delete_char_right(&mut self) {
        let is_not_cursor_rightmost = self.input_pos.0 != self.input.chars().count();
        if is_not_cursor_rightmost {
            // Method "remove" is not used on the saved text for deleting the selected char.
            // Reason: Using remove on String works on bytes instead of the chars.
            // Using remove would require special care because of char boundaries.

            let current_index = self.input_pos.0;
            let from_right_to_current_index = current_index + 1;

            // Getting all characters before the selected character.
            let before_char_to_delete = self.input.chars().take(current_index);
            // Getting all characters after selected character.
            let after_char_to_delete = self.input.chars().skip(from_right_to_current_index);

            // Put all characters together except the selected one.
            // By leaving the selected one out, it is forgotten and therefore deleted.
            self.input = before_char_to_delete.chain(after_char_to_delete).collect();
        }
    }

    fn select_first(&mut self) {
        self.list_state.select_first();
    }

    fn select_last(&mut self) {
        self.list_state.select_last();
    }

    fn scroll_down_by(&mut self, amount: u16) {
        self.list_state.scroll_down_by(amount);
    }

    fn scroll_up_by(&mut self, amount: u16) {
        self.list_state.scroll_up_by(amount);
    }

    fn select_next(&mut self) {
        self.list_state.select_next();
    }

    fn select_previous(&mut self) {
        self.list_state.select_previous();
    }
}

impl StatefulWidgetRef for &SearchPopupWidget {
    type State = SearchPopupState;

    fn render_ref(&self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let popup_area = popup_area_percent(area, 80, 80);
        Clear.render(popup_area, buf);

        // FIXME: fork and update
        let matcher = SkimMatcherV2::default();

        let mut items = state
            .existing
            .iter()
            .filter_map(|e| {
                matcher
                    .fuzzy_match(e, &state.input)
                    .map(|score| (e, contains_case_insensitive(&state.input, e), score))
            })
            .collect::<Vec<_>>();

        items.sort_unstable_by(|a, b| a.2.cmp(&b.2).reverse());
        state.selected = state.list_state.selected().and_then(|s| {
            items
                .get(s)
                .map(|(choice, _exact, _score)| (*choice).clone())
        });

        let title = Line::from(self.title.as_str())
            .centered()
            .style(HEADER_ACTIVE_STYLE);

        let (instructions, count) = if let Some(selected) = state.list_state.selected() {
            (
                Line::default()
                    .spans([
                        Span::raw(" Discard "),
                        Span::styled("<esc> ", KEY_HINT_STYLE),
                        Span::raw(" Add match filter "),
                        Span::styled("<enter> ", KEY_HINT_STYLE),
                    ])
                    .centered(),
                Line::from(format!(
                    " {}/{} ",
                    (selected + 1).min(items.len()),
                    items.len()
                ))
                .left_aligned(),
            )
        } else {
            (
                Line::default()
                    .spans([
                        Span::raw(" Discard "),
                        Span::styled("<esc> ", KEY_HINT_STYLE),
                    ])
                    .centered(),
                Line::from(format!(" {} ", items.len())).left_aligned(),
            )
        };
        let block = Block::bordered()
            .border_set(border::THICK)
            .title(title)
            .title_bottom(instructions)
            .title_bottom(count);

        let inner_area = block.inner(popup_area);

        let [input_area, results_area] =
            Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).areas(inner_area);

        let w = &block;
        w.render_ref(popup_area, buf);

        {
            let block = Block::bordered().border_set(border::PLAIN);

            if state.input.is_empty() {
                let input =
                    Paragraph::new(Text::from(self.hint.as_str()).style(HIDDEN_STYLE)).block(block);

                input.render(input_area, buf);
            } else {
                let input_line = Line::from(state.input.as_str());

                let input = Paragraph::new(Text::from(input_line)).block(block);

                input.render(input_area, buf);
            }
        }

        {
            let items = items.into_iter().map(|(choice, exact, _score)| {
                let line = choice.as_str();
                if exact {
                    Line::from(line)
                } else {
                    Line::from(line).style(HIDDEN_STYLE)
                }
            });

            let list = List::new(items)
                .scroll_padding(1)
                .style(Style::default())
                .highlight_style(ACTIVE_ENTRY_HIGHLIGHT_STYLE)
                .scroll_padding(1);

            let [results_area] = Layout::default()
                .constraints(Constraint::from_fills([1]))
                .horizontal_margin(1)
                .areas(results_area);

            StatefulWidget::render(list, results_area, buf, &mut state.list_state);
        }

        #[expect(
            clippy::cast_possible_truncation,
            reason = "input should not exceed u16"
        )]
        {
            state.cursor_pos = Position::new(
                input_area.x + state.input_pos.0 as u16 + 1,
                input_area.y + 1,
            );
        }
    }
}

struct EventPopupWidget<'a> {
    paragraph: Paragraph<'a>,
}

impl<'a> EventPopupWidget<'a> {
    #[must_use]
    fn new(event: &'a ModSecurityEvent, event_index: usize, total_events: usize) -> Self {
        macro_rules! make_span {
            ($e: expr) => {
                $e.as_ref()
                    .map_or(Span::styled("<none>", HIDDEN_STYLE), |x| {
                        Span::from(x.to_string())
                    })
            };
            ($e: expr, $m: ident) => {
                $e.as_ref()
                    .map_or(Span::styled("<none>", HIDDEN_STYLE), |x| {
                        Span::from(x.$m.to_string())
                    })
            };
        }

        let mut text = Text::default();
        text.push_line(Span::from(" Event ID:             ").bold().white());
        text.push_span(Span::from(event.id.clone()));

        text.push_line(Span::from(" Timestamp:            ").bold().white());
        text.push_span(event.date.map_or_else(
            || Span::styled("<none>", HIDDEN_STYLE),
            |d| Span::from(d.format(&Rfc2822).expect("timestamp and format are valid")),
        ));

        text.push_line(Span::from(" Source IP:            ").bold().white());
        text.push_span(make_span!(event.source_ip));

        text.push_line(Span::from(" Source Port:          ").bold().white());
        text.push_span(make_span!(event.source_port));

        text.push_line(Span::from(" Destination IP:       ").bold().white());
        text.push_span(make_span!(event.destination_ip));

        text.push_line(Span::from(" Destination Port:     ").bold().white());
        text.push_span(make_span!(event.destination_port));

        text.push_line(Span::from(" Rule ID:              ").bold().white());
        text.push_span(make_span!(event.rule_details, id));

        text.push_line(Span::from(" Rule Description:     ").bold().white());
        text.push_span(make_span!(event.rule_details, description));

        text.push_line(Span::from(" Rule Severity:        ").bold().white());
        text.push_span(make_span!(event.rule_details, severity));

        text.push_line(Span::from(" Rule Data:            ").bold().white());
        text.push_span(make_span!(
            event.rule_details.as_ref().and_then(|rd| rd.data.as_ref())
        ));

        text.push_line(Span::from(" HTTP Status Code:     ").bold().white());
        text.push_span(make_span!(event.http_status, code));

        text.push_line(Span::from(" HTTP Status Message:  ").bold().white());
        text.push_span(make_span!(event.http_status, message));

        text.push_line(Span::from(" Requested Host:       ").bold().white());
        text.push_span(make_span!(event.requested_host));

        text.push_line(Span::from(" Requested Path:       ").bold().white());
        text.push_span(make_span!(event.requested_path));

        text.push_line(Span::from(" User Agent:           ").bold().white());
        text.push_span(make_span!(event.user_agent));

        let title = Line::from(" Event Details ")
            .centered()
            .style(HEADER_ACTIVE_STYLE);
        let position =
            Line::from(format!(" {}/{} ", event_index + 1, total_events)).right_aligned();
        let instructions = Line::default()
            .spans([
                Span::raw(" Select "),
                Span::styled("<up/down> ", KEY_HINT_STYLE),
                Span::raw(" Close "),
                Span::styled("<esc> ", KEY_HINT_STYLE),
            ])
            .centered();
        let block = Block::bordered()
            .title(title)
            .title_top(position)
            .title_bottom(instructions)
            .border_set(border::PLAIN);

        let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: false });

        Self { paragraph }
    }
}

impl WidgetRef for &EventPopupWidget<'_> {
    fn render_ref(&self, area: Rect, buf: &mut Buffer) {
        let popup_area = popup_area_percent(area, 80, 80);
        Clear.render(popup_area, buf);

        let w = &self.paragraph;
        w.render_ref(popup_area, buf);
    }
}

struct WarningsWidget<'a> {
    items: Vec<ListItem<'a>>,
}

impl<'a> WarningsWidget<'a> {
    #[must_use]
    fn new(warnings: &'a [String]) -> Self {
        let items = warnings.iter().map(|s| s.as_str().into()).collect();

        Self { items }
    }

    #[must_use]
    fn handle_keyevent(key: KeyEvent, state: &mut ListState) -> Action {
        if key.kind == KeyEventKind::Press {
            match key.code {
                KeyCode::Down => state.select_next(),
                KeyCode::Up => state.select_previous(),
                KeyCode::PageDown => state.scroll_down_by(SCROLL_COUNT),
                KeyCode::PageUp => state.scroll_up_by(SCROLL_COUNT),
                KeyCode::Home => state.select_first(),
                KeyCode::End => state.select_last(),
                KeyCode::Esc => {
                    if state.selected().is_none() {
                        return Action::Unselect;
                    }
                    state.select(None);
                }
                _ => {}
            }
        }
        Action::None
    }
}

impl<'a> StatefulWidgetRef for &'a WarningsWidget<'a> {
    type State = (&'a mut ListState, ActivePanel);

    fn render_ref(&self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let (list_state, active_panel) = state;
        let is_active: bool = *active_panel == ActivePanel::WarningsPanel;

        let block = if is_active {
            let title = if let Some(index) = list_state.selected() {
                format!(
                    " Warnings ({}/{}) ",
                    (index.saturating_add(1)).min(self.items.len()),
                    self.items.len()
                )
            } else {
                format!(" Warnings ({}) ", self.items.len())
            };
            let title = Line::from(title).centered().style(HEADER_ACTIVE_STYLE);
            Block::bordered().title(title).border_set(border::THICK)
        } else {
            let title = Line::from(format!(" Warnings ({}) ", self.items.len()))
                .centered()
                .style(HEADER_INACTIVE_STYLE);
            let mut block = Block::bordered().title(title).border_set(border::PLAIN);

            if *active_panel == ActivePanel::None {
                block = block.title_bottom(ActivePanel::WarningsPanel.hint());
            }

            block
        };

        let highlight_style = if is_active {
            ACTIVE_ENTRY_HIGHLIGHT_STYLE
        } else {
            INACTIVE_ENTRY_HIGHLIGHT_STYLE
        };

        let list = List::new(self.items.iter().cloned()) // FIXME: avoid clone
            .block(block)
            .scroll_padding(1)
            .style(Style::default())
            //.highlight_symbol("> ")
            .highlight_style(highlight_style);

        if is_active {
            StatefulWidget::render(list, area, buf, list_state);
        } else {
            Widget::render(list, area, buf);
        }
    }
}

struct EventsWidget<'a> {
    parsed_stats: Option<&'a Statistics>,
    filtered_stats: Option<&'a Statistics>,
    items: Vec<ListItem<'a>>,
    is_loaded: bool,
}

impl<'a> EventsWidget<'a> {
    #[must_use]
    fn new(
        events: Option<&'a [ModSecurityEvent]>,
        parsed_stats: Option<&'a Statistics>,
        filtered_stats: Option<&'a Statistics>,
    ) -> Self {
        let items = events.map_or(Vec::new(), |ev| {
            ev.iter().map(std::convert::Into::into).collect()
        });

        Self {
            parsed_stats,
            filtered_stats,
            items,
            is_loaded: events.is_some(),
        }
    }

    #[must_use]
    fn handle_keyevent(key: KeyEvent, state: &mut ListState) -> Action {
        if key.kind == KeyEventKind::Press {
            match key.code {
                KeyCode::Down => state.select_next(),
                KeyCode::Up => state.select_previous(),
                KeyCode::PageDown => state.scroll_down_by(SCROLL_COUNT),
                KeyCode::PageUp => state.scroll_up_by(SCROLL_COUNT),
                KeyCode::Home => state.select_first(),
                KeyCode::End => state.select_last(),
                KeyCode::Esc => {
                    if state.selected().is_none() {
                        return Action::Unselect;
                    }
                    state.select(None);
                }
                KeyCode::Char('s') => {
                    if let Some(index) = state.selected() {
                        return Action::AddFilter(AddFilterKind::SourceIpMatch, index);
                    }
                }
                KeyCode::Char('S') => {
                    if let Some(index) = state.selected() {
                        return Action::AddFilter(AddFilterKind::SourceIpExclude, index);
                    }
                }
                KeyCode::Char('p') | KeyCode::Enter => {
                    if let Some(index) = state.selected() {
                        return Action::ShowEventDetails(index);
                    }
                }
                _ => {}
            }
        }
        Action::None
    }
}

impl<'a> StatefulWidgetRef for &'a EventsWidget<'a> {
    type State = (&'a mut ListState, ActivePanel, bool);

    fn render_ref(&self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let (list_state, active_panel, has_active_filter) = state;
        let is_active: bool = *active_panel == ActivePanel::EventsPanel;
        let has_active_filter: bool = *has_active_filter;

        let filtered_stats = &self.filtered_stats;
        let parsed_stats = &self.parsed_stats;

        let tstr = parsed_stats
            .as_ref()
            .map_or_else(|| String::from("?"), |ps| ps.total_events.to_string());
        let rstr = parsed_stats
            .as_ref()
            .map_or_else(|| String::from("?"), |ps| ps.rule_events.to_string());

        let total_events = if has_active_filter {
            Line::default().spans([
                Span::raw(format!(
                    " Total Events: {}",
                    filtered_stats
                        .as_ref()
                        .map_or_else(|| String::from("?"), |fs| fs.total_events.to_string())
                )),
                Span::raw(format!("/{tstr}")).style(HIDDEN_STYLE),
                Span::raw(" "),
            ])
        } else {
            Line::from(format!(" Total: {tstr} "))
        };
        let rule_events = if has_active_filter {
            Line::default().spans([
                Span::raw(format!(
                    " With Rule: {}",
                    filtered_stats
                        .as_ref()
                        .map_or_else(|| String::from("?"), |fs| fs.rule_events.to_string())
                )),
                Span::raw(format!("/{rstr}")).style(HIDDEN_STYLE),
                Span::raw(" "),
            ])
        } else {
            Line::from(format!(" With Rule: {rstr} "))
        };
        let first_event_str = filtered_stats.as_ref().map_or_else(
            || String::from("?"),
            |fs| {
                fs.first_datetime
                    .and_then(|d| d.format(&Rfc2822).ok())
                    .unwrap_or_else(|| String::from("n/a"))
            },
        );
        let first_event = format!(" First: {first_event_str} ");
        let last_event_str = filtered_stats.as_ref().map_or_else(
            || String::from("?"),
            |fs| {
                fs.last_datetime
                    .and_then(|d| d.format(&Rfc2822).ok())
                    .unwrap_or_else(|| String::from("n/a"))
            },
        );
        let last_event = format!(" Last: {last_event_str} ");

        let title = if let Some(index) = list_state.selected() {
            format!(
                " Events ({}/{}) ",
                if self.is_loaded {
                    index.saturating_add(1).min(self.items.len()).to_string()
                } else {
                    String::from("?")
                },
                if self.is_loaded {
                    self.items.len().to_string()
                } else {
                    String::from("?")
                },
            )
        } else {
            format!(
                " Events ({}) ",
                if self.is_loaded {
                    self.items.len().to_string()
                } else {
                    String::from("?")
                }
            )
        };

        let block = if is_active {
            let title = Line::from(title).centered().style(HEADER_ACTIVE_STYLE);
            let instructions = if list_state.selected().is_some() {
                Line::default()
                    .spans([
                        Span::raw(" Show Details "),
                        Span::styled("<p> ", KEY_HINT_STYLE),
                        Span::raw("Match Source IP "),
                        Span::styled("<s> ", KEY_HINT_STYLE),
                    ])
                    .centered()
            } else {
                Line::default()
                    .spans([
                        Span::raw(" Select "),
                        Span::styled("<up/down> ", KEY_HINT_STYLE),
                    ])
                    .centered()
            };

            Block::bordered()
                .title(title)
                .title_bottom(instructions)
                .title_top(total_events.left_aligned())
                .title_bottom(Line::from(first_event).left_aligned())
                .title_bottom(Line::from(last_event).right_aligned())
                .title_top(rule_events.right_aligned())
                .border_set(border::THICK)
        } else {
            let title = Line::from(title).centered().style(HEADER_INACTIVE_STYLE);

            let median_event_str = filtered_stats.as_ref().map_or_else(
                || String::from("?"),
                |fs| {
                    fs.median_datetime
                        .and_then(|d| d.format(&Rfc2822).ok())
                        .unwrap_or_else(|| String::from("n/a"))
                },
            );
            let median_event = format!(" Median: {median_event_str} ");

            let mut block = Block::bordered()
                .title(title)
                .border_set(border::PLAIN)
                .title_top(total_events.left_aligned())
                .title_bottom(Line::from(first_event).left_aligned())
                .title_bottom(Line::from(median_event).centered())
                .title_bottom(Line::from(last_event).right_aligned())
                .title_top(rule_events.right_aligned());

            if *active_panel == ActivePanel::None {
                block = block.title_bottom(ActivePanel::EventsPanel.hint());
            }

            block
        };

        if !self.is_loaded {
            let paragraph = Paragraph::new("loading ...").block(block);
            paragraph.render(area, buf);
            return;
        }

        let highlight_style = if is_active {
            ACTIVE_ENTRY_HIGHLIGHT_STYLE
        } else {
            INACTIVE_ENTRY_HIGHLIGHT_STYLE
        };

        let event_list = List::new(self.items.iter().cloned()) // FIXME: avoid clone
            .block(block)
            .scroll_padding(1)
            .style(Style::default())
            .highlight_style(highlight_style);

        StatefulWidget::render(event_list, area, buf, list_state);
    }
}

struct DetailState<T: DetailWidgetImpl + ?Sized> {
    matched: Vec<usize>,
    excluded: Vec<usize>,
    custom: Vec<T::DetailType>,
    table: TableState,
}

impl<T: DetailWidgetImpl> DetailState<T> {
    #[must_use]
    fn new() -> Self {
        Self {
            matched: Vec::new(),
            excluded: Vec::new(),
            custom: Vec::new(),
            table: TableState::default().with_selected_column(Some(1)),
        }
    }

    fn reset(&mut self) {
        self.matched.clear();
        self.excluded.clear();
        self.custom.clear();
        self.table.select(None);
    }

    #[must_use]
    fn handle_keyevent(&mut self, key: KeyEvent) -> Action {
        if key.kind == KeyEventKind::Press {
            match key.code {
                KeyCode::Down => self.table.select_next(),
                KeyCode::Up => self.table.select_previous(),
                KeyCode::PageDown => self.table.scroll_down_by(SCROLL_COUNT),
                KeyCode::PageUp => self.table.scroll_up_by(SCROLL_COUNT),
                KeyCode::Home => self.table.select_first(),
                KeyCode::End => self.table.select_last(),
                KeyCode::Esc => {
                    if self.table.selected().is_none() {
                        return Action::Unselect;
                    }
                    self.table.select(None);
                }
                KeyCode::Enter if self.table.selected().is_none() => {
                    self.table.select_first();
                }
                KeyCode::Char('x') => {
                    if let Some(selected) = self.table.selected()
                        && selected >= self.custom.len()
                    {
                        let selected = selected - self.custom.len();
                        vec_del!(self.matched, selected);

                        if let Some(idx) = self.excluded.iter().position(|e| *e == selected) {
                            self.excluded.remove(idx);
                        } else {
                            self.excluded.push(selected);
                        }
                        return Action::FilterUpdate;
                    }
                }
                KeyCode::Delete | KeyCode::Backspace => {
                    if let Some(selected) = self.table.selected()
                        && selected < self.custom.len()
                    {
                        self.custom.remove(selected);
                        return Action::FilterUpdate;
                    }
                }
                KeyCode::Char('m') => {
                    if let Some(selected) = self.table.selected()
                        && selected >= self.custom.len()
                    {
                        let selected = selected - self.custom.len();
                        vec_del!(self.excluded, selected);

                        if let Some(idx) = self.matched.iter().position(|e| *e == selected) {
                            self.matched.remove(idx);
                        } else {
                            self.matched.push(selected);
                        }

                        return Action::FilterUpdate;
                    }
                }
                KeyCode::Char('c') => return Action::CustomInput,
                KeyCode::Char('/') => return Action::Search,
                _ => {}
            }
        }
        Action::None
    }
}

trait DetailWidgetImpl {
    const NAME: &'static str;

    const PANEL: ActivePanel;

    type DetailType: Clone + Eq + ToString;
    type StatisticType; // TODO: use `= Self::DetailType` default when stable

    #[must_use]
    fn get_data(stats: &Statistics) -> &[(Self::StatisticType, u64)];

    #[must_use]
    fn access_data(data: &Self::StatisticType) -> &Self::DetailType;

    #[must_use]
    fn create_match_filter(entries: Vec<Self::DetailType>) -> EventFilter;

    #[must_use]
    fn create_exclude_filter(entry: Self::DetailType) -> EventFilter;

    #[must_use]
    fn collect_entries(stats: &Statistics) -> Vec<String> {
        Self::get_data(stats)
            .iter()
            .map(|(entry, _)| Self::access_data(entry).to_string())
            .collect()
    }

    fn build_filters(
        global_stats: &Statistics,
        state: &DetailState<Self>,
    ) -> impl Iterator<Item = EventFilter> {
        let matched = if state.matched.is_empty() && state.custom.is_empty() {
            None
        } else {
            let mut entries = state
                .matched
                .iter()
                .map(|idx| {
                    let stats_data = &Self::get_data(global_stats)
                        .get(*idx)
                        .expect("valid index is an invariant of DetailPanelState")
                        .0;
                    let data = Self::access_data(stats_data);
                    data.clone()
                })
                .collect::<Vec<Self::DetailType>>();
            entries.extend_from_slice(&state.custom);
            Some(Self::create_match_filter(entries))
        };

        state
            .excluded
            .iter()
            .map(|e| {
                let stats_data = &Self::get_data(global_stats)
                    .get(*e)
                    .expect("valid index is an invariant of DetailPanelState")
                    .0;
                let data = Self::access_data(stats_data);
                Self::create_exclude_filter(data.clone())
            })
            .chain(matched)
    }

    #[must_use]
    fn display_data(detail_data: &Self::DetailType, _stats_data: &Self::StatisticType) -> String {
        detail_data.to_string()
    }

    fn render(
        &self, // unused
        area: Rect,
        buf: &mut Buffer,
        active_panel: ActivePanel,
        total_stats: Option<&Statistics>,
        filtered_stats: Option<&Statistics>,
        state: &mut DetailState<Self>,
    ) {
        const COLUMN_SPACING: u16 = 2;

        let total_items = total_stats.map(|s| Self::get_data(s));
        let filtered_items = filtered_stats.map(|s| Self::get_data(s));

        let is_active = active_panel == Self::PANEL;

        let tistr = total_items.map_or_else(|| String::from("?"), |t| t.len().to_string());

        let Some(filtered_items) = filtered_items else {
            let block = if is_active {
                let title = if let Some(index) = state.table.selected() {
                    Line::from(format!(
                        " {} ({}/{}) ",
                        Self::NAME,
                        total_items.map_or_else(
                            || String::from("?"),
                            |t| index.saturating_add(1).min(t.len()).to_string()
                        ),
                        tistr
                    ))
                    .centered()
                    .style(HEADER_ACTIVE_STYLE)
                } else {
                    let mut spans = vec![Span::styled(
                        format!(" {} ({}", Self::NAME, tistr),
                        HEADER_ACTIVE_STYLE,
                    )];
                    if !state.matched.is_empty() {
                        spans.push(Span::styled("|", HEADER_ACTIVE_STYLE));
                        spans.push(Span::from(state.matched.len().to_string()).green());
                    }
                    if !state.excluded.is_empty() {
                        spans.push(Span::styled("|", HEADER_ACTIVE_STYLE));
                        spans.push(Span::from(state.excluded.len().to_string()).red());
                    }
                    spans.push(Span::styled(") ", HEADER_ACTIVE_STYLE));

                    Line::default().spans(spans).bold().centered()
                };
                let instructions = if state.table.selected().is_some() {
                    Line::default()
                        .spans([
                            Span::raw(" Match "),
                            Span::styled("<m> ", KEY_HINT_STYLE),
                            Span::raw(" Exclude "),
                            Span::styled("<x> ", KEY_HINT_STYLE),
                        ])
                        .centered()
                } else {
                    Line::default()
                        .spans([
                            Span::raw(" Select "),
                            Span::styled("<up/down> ", KEY_HINT_STYLE),
                        ])
                        .centered()
                };
                Block::bordered()
                    .title(title)
                    .title_bottom(instructions)
                    .border_set(border::THICK)
            } else {
                let mut spans = vec![Span::styled(
                    format!(" {} ({}", Self::NAME, tistr),
                    HEADER_INACTIVE_STYLE,
                )];
                if !state.matched.is_empty() {
                    spans.push(Span::styled("|", HEADER_INACTIVE_STYLE));
                    spans.push(Span::from(state.matched.len().to_string()).green());
                }
                if !state.excluded.is_empty() {
                    spans.push(Span::styled("|", HEADER_INACTIVE_STYLE));
                    spans.push(Span::from(state.excluded.len().to_string()).red());
                }
                spans.push(Span::styled(") ", HEADER_INACTIVE_STYLE));
                let title = Line::default().spans(spans).centered();
                let mut block = Block::bordered().title(title).border_set(border::PLAIN);

                if active_panel == ActivePanel::None {
                    block = block.title_bottom(Self::PANEL.hint());
                }

                block
            };

            let paragraph = Paragraph::new("loading ...").block(block);
            paragraph.render(area, buf);
            return;
        };

        let widths = [Constraint::Percentage(20), Constraint::Percentage(80)];

        let block = if is_active {
            let title = if let Some(index) = state.table.selected() {
                let mut spans = vec![Span::styled(
                    format!(
                        " {} ({}/{tistr}",
                        Self::NAME,
                        total_items.map_or_else(
                            || String::from("?"),
                            |t| index.saturating_add(1).min(t.len()).to_string()
                        )
                    ),
                    HEADER_ACTIVE_STYLE,
                )];
                if !state.custom.is_empty() {
                    spans.push(Span::styled("|", HEADER_ACTIVE_STYLE));
                    spans.push(Span::from(state.custom.len().to_string()).cyan());
                }
                if !state.matched.is_empty() {
                    spans.push(Span::styled("|", HEADER_ACTIVE_STYLE));
                    spans.push(Span::from(state.matched.len().to_string()).green());
                }
                if !state.excluded.is_empty() {
                    spans.push(Span::styled("|", HEADER_ACTIVE_STYLE));
                    spans.push(Span::from(state.excluded.len().to_string()).red());
                }
                spans.push(Span::styled(") ", HEADER_ACTIVE_STYLE));

                Line::default().spans(spans).bold().centered()
            } else {
                let mut spans = vec![Span::styled(
                    format!(" {} ({tistr}", Self::NAME),
                    HEADER_ACTIVE_STYLE,
                )];
                if !state.custom.is_empty() {
                    spans.push(Span::styled("|", HEADER_ACTIVE_STYLE));
                    spans.push(Span::from(state.custom.len().to_string()).cyan());
                }
                if !state.matched.is_empty() {
                    spans.push(Span::styled("|", HEADER_ACTIVE_STYLE));
                    spans.push(Span::from(state.matched.len().to_string()).green());
                }
                if !state.excluded.is_empty() {
                    spans.push(Span::styled("|", HEADER_ACTIVE_STYLE));
                    spans.push(Span::from(state.excluded.len().to_string()).red());
                }
                spans.push(Span::styled(") ", HEADER_ACTIVE_STYLE));

                Line::default().spans(spans).bold().centered()
            };
            let instructions = match state.table.selected() {
                Some(x) if x < state.custom.len() => Line::default()
                    .spans([
                        Span::raw(" Remove "),
                        Span::styled("<del> ", KEY_HINT_STYLE),
                    ])
                    .centered(),
                Some(x) => {
                    let ins_match = if state.matched.contains(&x) {
                        " Del match filter "
                    } else {
                        " Add match filter "
                    };
                    let ins_exclude = if state.excluded.contains(&x) {
                        " Del exclude filter "
                    } else {
                        " Add exclude filter "
                    };

                    Line::default()
                        .spans([
                            Span::raw(ins_match),
                            Span::styled("<m> ", KEY_HINT_STYLE),
                            Span::raw(ins_exclude),
                            Span::styled("<x> ", KEY_HINT_STYLE),
                        ])
                        .centered()
                }
                None => Line::default()
                    .spans([
                        Span::raw(" Select "),
                        Span::styled("<up/down> ", KEY_HINT_STYLE),
                        Span::raw(" Custom "),
                        Span::styled("<c> ", KEY_HINT_STYLE),
                        Span::raw(" Search "),
                        Span::styled("</> ", KEY_HINT_STYLE),
                    ])
                    .centered(),
            };
            Block::bordered()
                .title(title)
                .title_bottom(instructions)
                .border_set(border::THICK)
        } else {
            let fistr = filtered_items.len().to_string();
            let mut spans = vec![Span::styled(
                format!(" {} ({fistr}", Self::NAME),
                HEADER_INACTIVE_STYLE,
            )];
            if total_items.is_none_or(|ti| ti.len() != filtered_items.len()) {
                spans.push(Span::styled("/", HEADER_INACTIVE_STYLE));
                spans.push(Span::from(tistr.as_str()).style(HIDDEN_STYLE));
            }
            if !state.custom.is_empty() {
                spans.push(Span::styled("|", HEADER_INACTIVE_STYLE));
                spans.push(Span::from(state.custom.len().to_string()).cyan());
            }
            if !state.matched.is_empty() {
                spans.push(Span::styled("|", HEADER_INACTIVE_STYLE));
                spans.push(Span::from(state.matched.len().to_string()).green());
            }
            if !state.excluded.is_empty() {
                spans.push(Span::styled("|", HEADER_INACTIVE_STYLE));
                spans.push(Span::from(state.excluded.len().to_string()).red());
            }
            spans.push(Span::styled(") ", HEADER_INACTIVE_STYLE));
            let title = Line::default().spans(spans).centered();
            let mut block = Block::bordered().title(title).border_set(border::PLAIN);

            if active_panel == ActivePanel::None {
                block = block.title_bottom(Self::PANEL.hint());
            }

            block
        };

        if let Some(total_items) = total_items {
            let customs = state.custom.iter().map(|c| {
                let count = total_items
                    .iter()
                    .find(|e| Self::access_data(&e.0) == c)
                    .map_or(0, |e| e.1);

                let filtered_count = filtered_items
                    .iter()
                    .find(|e| Self::access_data(&e.0) == c)
                    .map_or(0, |e| e.1);

                let style = Style::new().cyan();

                let text = if !is_active {
                    filtered_count.to_string()
                } else if count == filtered_count {
                    count.to_string()
                } else {
                    format!("{filtered_count} ({count})")
                };
                Row::new([
                    Cell::new(Text::from(text).right_aligned()),
                    Cell::new(c.to_string()),
                ])
                .style(style)
            });

            let rows = total_items
                .iter()
                .enumerate()
                .filter_map(|(idx, (stats_val, count))| {
                    let val = Self::access_data(stats_val);
                    let is_matched = state.matched.contains(&idx);
                    let is_excluded = state.excluded.contains(&idx);
                    let is_custom = state.custom.contains(val);
                    let filtered_count = filtered_items
                        .iter()
                        .find(|e| Self::access_data(&e.0) == val)
                        .map_or(0, |e| e.1);

                    let mut style = match (is_matched, is_excluded) {
                        (false, false) => {
                            if filtered_count == 0 {
                                if state.table.selected().is_some() {
                                    HIDDEN_STYLE
                                } else {
                                    return None;
                                }
                            } else {
                                Style::default()
                            }
                        }
                        (true, false) => Style::new().green(),
                        (false, true) => Style::new().red(),
                        (true, true) => unreachable!(),
                    };

                    if is_custom {
                        style = style.italic();
                    }

                    let text = if !is_active {
                        filtered_count.to_string()
                    } else if *count == filtered_count {
                        count.to_string()
                    } else {
                        format!("{filtered_count} ({count})")
                    };
                    Some(
                        Row::new([
                            Cell::new(Text::from(text).right_aligned()),
                            Cell::new(Self::display_data(val, stats_val)),
                        ])
                        .style(style),
                    )
                });

            let combined = customs.chain(rows);

            // TODO: pre-compute table or rows in new()
            // TODO: support scroll_padding()
            let table = Table::new(combined, widths)
                .column_spacing(COLUMN_SPACING)
                .block(block)
                .style(Style::default())
                //.highlight_symbol("> ")
                .row_highlight_style(Style::new().reversed())
                .cell_highlight_style(ACTIVE_ENTRY_HIGHLIGHT_STYLE);

            if is_active {
                StatefulWidget::render(table, area, buf, &mut state.table);
            } else {
                Widget::render(table, area, buf);
            }
        } else {
            let rows = [Row::new(["loading...", "loading..."])];
            // TODO: support scroll_padding()
            let table = Table::new(rows, widths) // TODO: use already allocated rows
                .column_spacing(COLUMN_SPACING)
                .block(block)
                .style(Style::default());

            Widget::render(table, area, buf);
        }
    }
}

struct SourceIpWidget {}

impl DetailWidgetImpl for SourceIpWidget {
    const NAME: &'static str = "Source IP";
    const PANEL: ActivePanel = ActivePanel::SourceIp;

    type DetailType = IpDetail;
    type StatisticType = IpDetail;

    fn get_data(stats: &Statistics) -> &[(Self::StatisticType, u64)] {
        stats.source_ips.as_slice()
    }

    fn access_data(data: &Self::StatisticType) -> &Self::DetailType {
        data
    }

    fn create_match_filter(ipnets: Vec<Self::DetailType>) -> EventFilter {
        EventFilter::SourceIpMatch(SourceIpMatch { ipnets })
    }

    fn create_exclude_filter(ipnet: Self::DetailType) -> EventFilter {
        EventFilter::SourceIpExclude(SourceIpExclude { ipnet })
    }
}

struct DestinationIpWidget {}

impl DetailWidgetImpl for DestinationIpWidget {
    const NAME: &'static str = "Destination IP";
    const PANEL: ActivePanel = ActivePanel::DestinationIp;

    type DetailType = IpDetail;
    type StatisticType = IpDetail;

    fn get_data(stats: &Statistics) -> &[(Self::StatisticType, u64)] {
        stats.destination_ips.as_slice()
    }

    fn access_data(data: &Self::StatisticType) -> &Self::DetailType {
        data
    }

    fn create_match_filter(ipnets: Vec<Self::DetailType>) -> EventFilter {
        EventFilter::DestinationIpMatch(DestinationIpMatch { ipnets })
    }

    fn create_exclude_filter(ipnet: Self::DetailType) -> EventFilter {
        EventFilter::DestinationIpExclude(DestinationIpExclude { ipnet })
    }
}

struct RuleIdWidget {}

impl DetailWidgetImpl for RuleIdWidget {
    const NAME: &'static str = "Rule ID";
    const PANEL: ActivePanel = ActivePanel::RuleId;

    type DetailType = RuleId;
    type StatisticType = RuleIdDesc;

    fn get_data(stats: &Statistics) -> &[(Self::StatisticType, u64)] {
        stats.rule_ids.as_slice()
    }

    fn access_data(data: &Self::StatisticType) -> &Self::DetailType {
        &data.id
    }

    fn display_data(_detail_data: &Self::DetailType, stats_data: &Self::StatisticType) -> String {
        format!("{} - {}", stats_data.id, stats_data.desc)
    }

    fn create_match_filter(ids: Vec<Self::DetailType>) -> EventFilter {
        EventFilter::RuleIdMatch(RuleIdMatch { ids })
    }

    fn create_exclude_filter(id: Self::DetailType) -> EventFilter {
        EventFilter::RuleIdExclude(RuleIdExclude { id })
    }
}

struct RuleSeverityWidget {}

impl DetailWidgetImpl for RuleSeverityWidget {
    const NAME: &'static str = "Rule Severity";
    const PANEL: ActivePanel = ActivePanel::RuleSeverity;

    type DetailType = DisplayRuleSeverity;
    type StatisticType = DisplayRuleSeverity;

    fn get_data(stats: &Statistics) -> &[(Self::StatisticType, u64)] {
        stats.rule_severities.as_slice()
    }

    fn access_data(data: &Self::StatisticType) -> &Self::DetailType {
        data
    }

    fn create_match_filter(sevs: Vec<Self::DetailType>) -> EventFilter {
        EventFilter::RuleSeverityMatch(RuleSeverityMatch { sevs })
    }

    fn create_exclude_filter(sev: Self::DetailType) -> EventFilter {
        EventFilter::RuleSeverityExclude(RuleSeverityExclude { sev })
    }
}

struct HttpStatusWidget {}

impl DetailWidgetImpl for HttpStatusWidget {
    const NAME: &'static str = "HTTP Status";
    const PANEL: ActivePanel = ActivePanel::HttpStatus;

    type DetailType = HttpStatusCode;
    type StatisticType = HttpStatus;

    fn get_data(stats: &Statistics) -> &[(Self::StatisticType, u64)] {
        stats.http_codes.as_slice()
    }

    fn access_data(data: &Self::StatisticType) -> &Self::DetailType {
        &data.code
    }

    fn create_match_filter(codes: Vec<Self::DetailType>) -> EventFilter {
        EventFilter::HttpStatusMatch(HttpStatusMatch { codes })
    }

    fn create_exclude_filter(code: Self::DetailType) -> EventFilter {
        EventFilter::HttpStatusExclude(HttpStatusExclude { code })
    }
}

struct HttpMethodWidget {}

impl DetailWidgetImpl for HttpMethodWidget {
    const NAME: &'static str = "HTTP Method";
    const PANEL: ActivePanel = ActivePanel::HttpMethod;

    type DetailType = String;
    type StatisticType = String;

    fn get_data(stats: &Statistics) -> &[(Self::StatisticType, u64)] {
        stats.http_methods.as_slice()
    }

    fn access_data(data: &Self::StatisticType) -> &Self::DetailType {
        data
    }

    fn create_match_filter(methods: Vec<Self::DetailType>) -> EventFilter {
        EventFilter::HttpMethodMatch(HttpMethodMatch { methods })
    }

    fn create_exclude_filter(method: Self::DetailType) -> EventFilter {
        EventFilter::HttpMethodExclude(HttpMethodExclude { method })
    }
}

struct RequestedHostWidget {}

impl DetailWidgetImpl for RequestedHostWidget {
    const NAME: &'static str = "Requested Host";
    const PANEL: ActivePanel = ActivePanel::RequestedHost;

    type DetailType = String;
    type StatisticType = String;

    fn get_data(stats: &Statistics) -> &[(Self::StatisticType, u64)] {
        stats.requested_hosts.as_slice()
    }

    fn access_data(data: &Self::StatisticType) -> &Self::DetailType {
        data
    }

    fn create_match_filter(hosts: Vec<Self::DetailType>) -> EventFilter {
        EventFilter::RequestedHostMatch(RequestedHostMatch { hosts })
    }

    fn create_exclude_filter(host: Self::DetailType) -> EventFilter {
        EventFilter::RequestedHostExclude(RequestedHostExclude { host })
    }
}

struct RequestedPathWidget {}

impl DetailWidgetImpl for RequestedPathWidget {
    const NAME: &'static str = "Requested Path";
    const PANEL: ActivePanel = ActivePanel::RequestedPath;

    type DetailType = String;
    type StatisticType = String;

    fn get_data(stats: &Statistics) -> &[(Self::StatisticType, u64)] {
        stats.requested_paths.as_slice()
    }

    fn access_data(data: &Self::StatisticType) -> &Self::DetailType {
        data
    }

    fn create_match_filter(paths: Vec<Self::DetailType>) -> EventFilter {
        EventFilter::RequestedPathMatch(RequestedPathMatch { paths })
    }

    fn create_exclude_filter(path: Self::DetailType) -> EventFilter {
        EventFilter::RequestedPathExclude(RequestedPathExclude { path })
    }
}
