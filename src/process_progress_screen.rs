use std::sync::mpsc;
use std::{io, path::PathBuf};

use crate::AppEvent;
use crate::AppTask;
use crate::Succession;
use crate::style::{KEY_HINT_STYLE, PROGRAM_TITLE_STYLE};

use hashbrown::HashMap;
use ratatui::crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};

use ratatui::DefaultTerminal;
use ratatui::prelude::*;
use ratatui::symbols::border;
use ratatui::widgets::{Block, Gauge, List, ListItem};

enum ShowWarnings {
    Initial,
    Enabled,
    Disabled,
}

pub(crate) struct ProcessProgressScreen {
    source_files: Vec<PathBuf>,
    current_file: PathBuf,
    total: usize,
    finished: usize,
    task_tx: mpsc::Sender<AppTask>,
    show_warnings: ShowWarnings,
}

impl ProcessProgressScreen {
    #[must_use]
    pub(crate) fn new(mut source_files: Vec<PathBuf>, task_tx: mpsc::Sender<AppTask>) -> Self {
        Self {
            total: source_files.len(),
            current_file: source_files.pop().expect("sources should not be empty"),
            source_files,
            finished: 0,
            task_tx,
            show_warnings: ShowWarnings::Initial,
        }
    }

    pub(crate) fn run(
        &mut self,
        terminal: &mut DefaultTerminal,
        event_rx: &mpsc::Receiver<AppEvent>,
    ) -> io::Result<Succession> {
        let mut parsed_events = Vec::new();
        let mut collected_rule_descriptions = HashMap::new();
        let mut collected_http_descriptions = HashMap::new();
        let mut warnings = Vec::new();
        let mut warning_items = Vec::new();

        self.task_tx
            .send(AppTask::ProcessFile(self.current_file.clone()))
            .expect("task thread should not die before TUI thread");

        loop {
            assert_eq!(warnings.len(), warning_items.len());

            terminal.draw(|frame| self.draw(frame, &warning_items))?;

            // Read the next event from the input thread.
            let event = event_rx
                .recv()
                .expect("event thread should not die before TUI thread");

            match event {
                AppEvent::Term(term_event) => {
                    if let Event::Key(key) = term_event
                        && key.kind == KeyEventKind::Press
                    {
                        match key.code {
                            KeyCode::Char('q' | 'Q') => {
                                return Ok(Succession::Quit);
                            }
                            KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                                return Ok(Succession::Quit);
                            }
                            KeyCode::Char('w') => {
                                self.show_warnings = match self.show_warnings {
                                    ShowWarnings::Initial => {
                                        if warnings.is_empty() {
                                            ShowWarnings::Enabled
                                        } else {
                                            ShowWarnings::Disabled
                                        }
                                    }
                                    ShowWarnings::Enabled => ShowWarnings::Disabled,
                                    ShowWarnings::Disabled => ShowWarnings::Enabled,
                                };
                            }

                            _ => {}
                        }
                    }
                }
                AppEvent::ProcessedFile(result) => {
                    match result {
                        Ok((
                            mut events,
                            rule_descriptions,
                            http_descriptions,
                            mut parse_warnings,
                        )) => {
                            parsed_events.append(&mut events);
                            collected_rule_descriptions.extend(rule_descriptions);
                            collected_http_descriptions.extend(http_descriptions);
                            warning_items.extend(parse_warnings.iter().map(|w| w.clone().into()));
                            warnings.append(&mut parse_warnings);
                        }
                        Err(err) => {
                            // TODO: handle errors differently?
                            warning_items.push(err.clone().into());
                            warnings.push(err);
                        }
                    }

                    self.finished += 1;

                    if let Some(file_to_process) = self.source_files.pop() {
                        assert!(self.finished < self.total);

                        self.current_file.clone_from(&file_to_process);
                        self.task_tx
                            .send(AppTask::ProcessFile(file_to_process))
                            .expect("task thread should not die before TUI thread");
                    } else {
                        assert!(self.finished == self.total);

                        return Ok(Succession::Overview((
                            parsed_events,
                            collected_rule_descriptions,
                            collected_http_descriptions,
                            warnings,
                        )));
                    }
                }
                AppEvent::ProcessedFilters(_, _, _) => unreachable!(),
                AppEvent::CalculatedSummary(_) => unreachable!(),
            }
        }
    }

    fn draw<'a>(&'a mut self, frame: &mut Frame<'_>, mut warning_items: &'a [ListItem<'a>]) {
        frame.render_stateful_widget(self, frame.area(), &mut warning_items);
    }
}

impl<'a> StatefulWidget for &'a mut ProcessProgressScreen {
    type State = &'a [ListItem<'a>];
    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State)
    where
        Self: Sized,
    {
        let warnings: &[ListItem<'_>] = state;

        let display_warnings = match self.show_warnings {
            ShowWarnings::Initial => !warnings.is_empty(),
            ShowWarnings::Enabled => true,
            ShowWarnings::Disabled => false,
        };

        let title = Line::from(" ModSecLog :: Processing Files ... ")
            .centered()
            .style(PROGRAM_TITLE_STYLE);
        let instructions = Line::default()
            .spans([
                Span::raw(" Hide/Show warnings "),
                Span::styled("<w> ", KEY_HINT_STYLE),
                Span::raw(" Quit "),
                Span::styled("<q> ", KEY_HINT_STYLE),
            ])
            .centered();

        let mut main_block = Block::bordered()
            .title(title)
            .title_bottom(instructions)
            .border_set(border::PLAIN);
        if !display_warnings {
            let mut warnings_hint = Line::from(format!(" Warnings ({}) ", warnings.len()))
                .white()
                .left_aligned();
            if !warnings.is_empty() {
                warnings_hint = warnings_hint.bold();
            }
            main_block = main_block.title_bottom(warnings_hint);
        }

        let inner_area = main_block.inner(area);

        main_block.render(area, buf);

        let main_layout =
            Layout::vertical([Constraint::Fill(1), Constraint::Max(4), Constraint::Fill(1)]);
        let [_top_area, center_area, bottom_area] = main_layout.areas(inner_area);

        let bottom_layout = if display_warnings {
            Layout::vertical([Constraint::Max(5), Constraint::Fill(1)])
        } else {
            Layout::vertical(Constraint::from_percentages([100, 0]))
        };
        let [_empty_area, warnings_area] = bottom_layout.areas(bottom_area);

        {
            let height = warnings_area.height.saturating_sub(2) as usize;
            let items = if warnings.len() < height {
                warnings
            } else {
                let start = warnings.len() - height;
                &warnings[start..]
            };

            let warnings_title = Line::from(format!(" Warnings ({}) ", warnings.len()))
                .bold()
                .white()
                .left_aligned();
            let selected =
                List::new(items.iter().cloned()).block(Block::bordered().title(warnings_title)); // FIXME: avoid clone
            Widget::render(selected, warnings_area, buf);
        }

        let center_layout = Layout::vertical(Constraint::from_mins([1, 3]));
        let [_filename_area, bar_area] = center_layout.areas(center_area);

        let current_filename = self.current_file.to_string_lossy();
        let filename = Line::default()
            .spans([
                Span::raw(" Processing "),
                Span::from(current_filename).italic().not_bold().blue(),
                Span::raw(" ... "),
            ])
            .centered();
        //filename.render(filename_area, buf);

        let bar_layout = Layout::horizontal([Constraint::Fill(1)]);
        let [progress_bar_area] = bar_layout.areas(bar_area);

        let block = Block::bordered().border_set(border::PLAIN).title(filename);
        #[expect(clippy::cast_precision_loss)]
        let ratio = self.finished as f64 / self.total as f64;
        let progress_bar = Gauge::default()
            .block(block)
            .label(format!(" {}/{}", self.finished, self.total))
            .ratio(ratio);
        progress_bar.render(progress_bar_area, buf);
    }
}
