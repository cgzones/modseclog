use std::sync::mpsc;
use std::{io, path::PathBuf};

use crate::AppEvent;
use crate::Succession;
use crate::style::{HIDDEN_STYLE, KEY_HINT_STYLE, PROGRAM_TITLE_STYLE, SCROLL_COUNT};

use ratatui::crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::prelude::*;
use ratatui::widgets::{ListItem, StatefulWidget};
use ratatui::{
    DefaultTerminal,
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::Style,
    symbols::border,
    text::Line,
    widgets::{Block, FrameExt as _, List, ListState, StatefulWidgetRef, WidgetRef as _},
};

use ratatui_explorer::{FileExplorer, Theme};

#[derive(Copy, Clone, Eq, PartialEq)]
enum ActivePanel {
    FileExplorer,
    SelectedFiles,
}

pub(crate) struct SourceSelectionScreen {}

impl SourceSelectionScreen {
    #[must_use]
    fn fe_active_theme() -> Theme {
        Theme::default()
            .with_title_top(|file_explorer: &FileExplorer| {
                Line::from(format!(" {} ", file_explorer.cwd().display()))
                    .italic()
                    .bold()
                    .white()
            })
            .with_block(Block::bordered().border_set(border::THICK))
            .with_scroll_padding(1)
    }

    #[must_use]
    fn fe_inactive_theme() -> Theme {
        Theme::default()
            .with_title_top(|file_explorer: &FileExplorer| {
                Line::from(format!(" {} ", file_explorer.cwd().display()))
                    .italic()
                    .white()
            })
            .with_block(Block::bordered().border_set(border::PLAIN))
            .with_highlight_dir_style(Style::default())
            .with_highlight_item_style(Style::default())
    }

    pub(crate) fn run(
        terminal: &mut DefaultTerminal,
        event_rx: &mpsc::Receiver<AppEvent>,
    ) -> io::Result<Succession> {
        let mut selected_files = Vec::new();
        let mut selected_state = ListState::default();
        let mut active_panel = ActivePanel::FileExplorer;
        let mut file_explorer = FileExplorer::with_theme(Self::fe_active_theme())?;
        let mut elements = None;

        loop {
            let e = if let Some(ref mut e) = elements {
                e
            } else {
                let w = SourceSelectionScreenWidget::new(&selected_files);
                elements = Some(w);
                elements.as_mut().expect("just assigned")
            };

            terminal.draw(|frame| {
                frame.render_stateful_widget_ref(
                    &*e,
                    frame.area(),
                    &mut (&mut selected_state, &mut file_explorer, active_panel),
                );
            })?;

            // Read the next event from the input thread.
            let event = event_rx
                .recv()
                .expect("event thread should not die before TUI thread");

            if let AppEvent::Term(term_event) = event {
                if let Event::Key(key) = term_event
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Char('q' | 'Q') => return Ok(Succession::Quit),
                        KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                            return Ok(Succession::Quit);
                        }
                        KeyCode::Char(' ') if !selected_files.is_empty() => {
                            return Ok(Succession::ProcessFiles(selected_files));
                        }
                        KeyCode::Tab | KeyCode::BackTab => {
                            elements = None;
                            match active_panel {
                                ActivePanel::FileExplorer => {
                                    active_panel = ActivePanel::SelectedFiles;
                                    file_explorer.set_theme(Self::fe_inactive_theme());
                                }
                                ActivePanel::SelectedFiles => {
                                    active_panel = ActivePanel::FileExplorer;
                                    file_explorer.set_theme(Self::fe_active_theme());
                                }
                            }
                        }
                        KeyCode::Down if active_panel == ActivePanel::SelectedFiles => {
                            selected_state.select_next();
                        }
                        KeyCode::Up if active_panel == ActivePanel::SelectedFiles => {
                            selected_state.select_previous();
                        }
                        KeyCode::PageDown if active_panel == ActivePanel::SelectedFiles => {
                            selected_state.scroll_down_by(SCROLL_COUNT);
                        }
                        KeyCode::PageUp if active_panel == ActivePanel::SelectedFiles => {
                            selected_state.scroll_up_by(SCROLL_COUNT);
                        }
                        KeyCode::Home if active_panel == ActivePanel::SelectedFiles => {
                            selected_state.select_first();
                        }
                        KeyCode::End if active_panel == ActivePanel::SelectedFiles => {
                            selected_state.select_last();
                        }
                        KeyCode::Esc if active_panel == ActivePanel::SelectedFiles => {
                            selected_state.select(None);
                        }
                        KeyCode::Enter | KeyCode::Right
                            if active_panel == ActivePanel::FileExplorer =>
                        {
                            let selected = file_explorer.current();
                            if selected.is_file() {
                                let mut found = false;

                                for (i, p) in selected_files.iter().enumerate() {
                                    if p == selected.path() {
                                        found = true;
                                        if key.code == KeyCode::Enter {
                                            elements = None;
                                            selected_files.remove(i);
                                        }
                                        break;
                                    }
                                }

                                if !found {
                                    elements = None;
                                    selected_files.push(selected.path().clone());
                                }

                                selected_state.select(None);
                            }
                        }
                        KeyCode::Delete if active_panel == ActivePanel::SelectedFiles => {
                            if let Some(index) = selected_state.selected() {
                                elements = None;
                                selected_files.remove(index);
                            }
                        }
                        _ => {}
                    }
                }

                if active_panel == ActivePanel::FileExplorer {
                    // Handle the event in the file explorer.
                    file_explorer.handle(&term_event)?;
                }
            }
        }
    }
}

struct SourceSelectionScreenWidget<'a> {
    items: Vec<ListItem<'a>>,
}

impl<'a> SourceSelectionScreenWidget<'a> {
    #[must_use]
    fn new(selected_files: &'a [PathBuf]) -> Self {
        let items = selected_files
            .iter()
            .map(|path| path.to_string_lossy().into())
            .collect::<Vec<ListItem<'_>>>();

        Self { items }
    }
}

impl<'a> StatefulWidgetRef for &SourceSelectionScreenWidget<'a> {
    type State = (&'a mut ListState, &'a mut FileExplorer, ActivePanel);

    fn render_ref(&self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let (selected_state, file_explorer, active_panel) = state;

        let title = Line::from(" ModSecLog :: Log File Selection ")
            .centered()
            .style(PROGRAM_TITLE_STYLE);

        let select_style = if file_explorer.current().is_file() {
            Style::default()
        } else {
            HIDDEN_STYLE
        };

        let finish_style = if self.items.is_empty() {
            HIDDEN_STYLE
        } else {
            Style::default()
        };

        let instructions = match active_panel {
            ActivePanel::FileExplorer => Line::default()
                .spans([
                    Span::styled(" Select file ", select_style),
                    Span::styled("<enter> ", KEY_HINT_STYLE),
                    Span::styled(" Finish selection ", finish_style),
                    Span::styled("<space> ", KEY_HINT_STYLE),
                    Span::from(" Quit "),
                    Span::styled("<q> ", KEY_HINT_STYLE),
                ])
                .centered(),

            ActivePanel::SelectedFiles => Line::default()
                .spans([
                    Span::styled(" Remove file ", finish_style),
                    Span::styled("<del> ", KEY_HINT_STYLE),
                    Span::styled(" Finish selection ", finish_style),
                    Span::styled("<space> ", KEY_HINT_STYLE),
                    Span::raw(" Quit "),
                    Span::styled("<q> ", KEY_HINT_STYLE),
                ])
                .centered(),
        };

        let main_block = Block::bordered()
            .title(title)
            .title_bottom(instructions)
            .border_set(border::PLAIN);

        let inner_area = main_block.inner(area);

        main_block.render(area, buf);

        let vertical_layout = Layout::vertical(Constraint::from_percentages([70, 30]));
        let [fileexplorer_area, selected_area] = vertical_layout.areas(inner_area);

        file_explorer.widget().render_ref(fileexplorer_area, buf);

        if selected_state.selected().is_none() {
            let height = selected_area.height.saturating_sub(2) as usize;
            let size = self.items.len();
            if size >= height {
                let offset = selected_state.offset_mut();
                *offset = size - height;
            }
        }

        let selected_list = match active_panel {
            ActivePanel::FileExplorer => {
                let selected_title =
                    Line::from(format!(" Selected Files ({}) ", self.items.len()).white())
                        .left_aligned();
                List::new(self.items.iter().cloned()) // FIXME: avoid clone
                    .block(
                        Block::bordered()
                            .title(selected_title)
                            .border_set(border::PLAIN),
                    )
                    .scroll_padding(1)
            }
            ActivePanel::SelectedFiles => {
                let selected_title = Line::from(
                    format!(" Selected Files ({}) ", self.items.len())
                        .white()
                        .bold(),
                )
                .left_aligned();
                List::new(self.items.iter().cloned()) // FIXME: avoid clone
                    .block(
                        Block::bordered()
                            .title(selected_title)
                            .border_set(border::THICK),
                    )
                    .scroll_padding(1)
                    //.highlight_symbol("> ")
                    .highlight_style(Style::new().bold().italic().blue())
            }
        };

        StatefulWidget::render(selected_list, selected_area, buf, selected_state);
    }
}
