use ratatui::layout::{Constraint, Flex, Layout, Rect};

#[must_use]
pub(crate) fn popup_area_percent(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::vertical([Constraint::Percentage(percent_y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

#[must_use]
pub(crate) fn popup_area_absolute(area: Rect, size_x: u16, size_y: u16) -> Rect {
    let vertical = Layout::vertical([Constraint::Length(size_y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Length(size_x)]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}
