use ratatui::style::{Color, Modifier, Style};

pub(crate) const PROGRAM_TITLE_STYLE: Style =
    Style::new().add_modifier(Modifier::BOLD).fg(Color::Magenta);
pub(crate) const HEADER_INACTIVE_STYLE: Style = Style::new().fg(Color::LightMagenta);
pub(crate) const HEADER_ACTIVE_STYLE: Style =
    Style::new().add_modifier(Modifier::BOLD).fg(Color::Blue);
pub(crate) const KEY_HINT_STYLE: Style = Style::new()
    .add_modifier(Modifier::BOLD)
    .add_modifier(Modifier::ITALIC)
    .fg(Color::Blue);
pub(crate) const PANEL_HINT_STYLE: Style = Style::new().fg(Color::Cyan);
pub(crate) const HIDDEN_STYLE: Style = Style::new()
    .add_modifier(Modifier::BOLD)
    .fg(Color::DarkGray);
pub(crate) const ACTIVE_ENTRY_HIGHLIGHT_STYLE: Style = Style::new()
    .fg(Color::Blue)
    .add_modifier(Modifier::REVERSED);
pub(crate) const INACTIVE_ENTRY_HIGHLIGHT_STYLE: Style =
    Style::new().fg(Color::Blue).add_modifier(Modifier::ITALIC);

pub(crate) const SCROLL_COUNT: u16 = 10;
