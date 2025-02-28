#![cfg_attr(
    test,
    allow(clippy::map_unwrap_or, clippy::unwrap_used, clippy::too_many_lines)
)]

use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread::{self};

use crate::event_filter::{EventFilter, EventFilterImpl};
use crate::mod_security::{HttpStatusCode, ModSecParseRes, ModSecurityEvent, RuleId};
use crate::overview_screen::OverviewScreen;
use crate::process_progress_screen::ProcessProgressScreen;
use crate::source_selection_screen::SourceSelectionScreen;
use crate::summary::{Statistics, calc_summary};

use clap::Parser;
use hashbrown::HashMap;
use ratatui::DefaultTerminal;

mod event_filter;
mod mod_security;
mod overview_screen;
mod process_progress_screen;
mod ratatui_utils;
mod source_selection_screen;
mod style;
mod summary;
mod utils;

enum AppScreen {
    SourceSelection,
    ProcessProgress(ProcessProgressScreen),
    Overview(Box<OverviewScreen>),
}

pub(crate) enum Succession {
    Quit,
    ProcessFiles(Vec<PathBuf>),
    Overview(ModSecParseRes),
}

impl AppScreen {
    fn run(
        &mut self,
        terminal: &mut DefaultTerminal,
        event_rx: &mpsc::Receiver<AppEvent>,
    ) -> io::Result<Succession> {
        match self {
            Self::SourceSelection => SourceSelectionScreen::run(terminal, event_rx),
            Self::ProcessProgress(screen) => screen.run(terminal, event_rx),
            Self::Overview(screen) => screen.run(terminal, event_rx),
        }
    }
}

struct MainApp {
    current_screen: AppScreen,
    event_rx: mpsc::Receiver<AppEvent>,
    task_tx: mpsc::Sender<AppTask>,
}

impl MainApp {
    fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        loop {
            match self.current_screen.run(terminal, &self.event_rx)? {
                Succession::Quit => break,
                Succession::ProcessFiles(sources) => {
                    self.current_screen = AppScreen::ProcessProgress(ProcessProgressScreen::new(
                        sources,
                        self.task_tx.clone(),
                    ));
                    continue;
                }
                Succession::Overview((
                    mut events,
                    rule_descriptions,
                    http_descriptions,
                    warnings,
                )) => {
                    events.sort_by(|a, b| a.date.cmp(&b.date).reverse());
                    self.current_screen = AppScreen::Overview(Box::new(OverviewScreen::new(
                        events,
                        rule_descriptions,
                        http_descriptions,
                        warnings,
                        self.task_tx.clone(),
                    )));
                    continue;
                }
            }
        }

        Ok(())
    }

    fn new(input_files: Option<Vec<PathBuf>>) -> Self {
        let (event_tx, event_rx) = mpsc::channel::<AppEvent>();

        // Thread to listen for input events.
        let tx_to_input_events = event_tx.clone();
        thread::spawn(move || {
            handle_input_events(tx_to_input_events);
        });

        let (task_tx, task_rx) = mpsc::channel::<AppTask>();

        // Thread to process tasks.
        let tx_to_tasks = event_tx;
        thread::spawn(move || {
            handle_tasks(task_rx, tx_to_tasks);
        });

        let start_screen = if let Some(input_files) = input_files {
            AppScreen::ProcessProgress(ProcessProgressScreen::new(input_files, task_tx.clone()))
        } else {
            AppScreen::SourceSelection
        };

        Self {
            current_screen: start_screen,
            //event_tx,
            event_rx,
            task_tx,
        }
    }
}

enum AppEvent {
    Term(ratatui::crossterm::event::Event),
    ProcessedFile(Result<ModSecParseRes, String>),
    CalculatedSummary(Statistics),
    ProcessedFilters(u32, Vec<ModSecurityEvent>, Statistics),
}

fn handle_input_events(tx: mpsc::Sender<AppEvent>) {
    loop {
        let event = ratatui::crossterm::event::read().expect("require a working terminal");
        if tx.send(AppEvent::Term(event)).is_err() {
            /* MainApp is dead, exit */
            break;
        }
    }
}

enum AppTask {
    ProcessFile(PathBuf),
    CalcSummary(
        Vec<ModSecurityEvent>,
        HashMap<RuleId, String>,
        HashMap<HttpStatusCode, String>,
    ),
    ProcessFilters(
        u32,
        Vec<ModSecurityEvent>,
        Vec<EventFilter>,
        HashMap<RuleId, String>,
        HashMap<HttpStatusCode, String>,
    ),
}

fn handle_tasks(rx: mpsc::Receiver<AppTask>, tx: mpsc::Sender<AppEvent>) {
    loop {
        let task = match rx.recv() {
            Ok(t) => t,
            Err(_err) => {
                /* MainApp is dead */
                return;
            }
        };

        match task {
            AppTask::ProcessFile(file) => {
                let result = mod_security::parse(&file);
                let result = result
                    .map_err(|err| format!("Failed to parse file {}: {}", file.display(), err));
                if tx.send(AppEvent::ProcessedFile(result)).is_err() {
                    /* MainApp is dead */
                    return;
                }
            }
            AppTask::CalcSummary(events, rule_descriptions, http_descriptions) => {
                let stats = calc_summary(&events, &rule_descriptions, &http_descriptions);

                if tx.send(AppEvent::CalculatedSummary(stats)).is_err() {
                    /* MainApp is dead */
                    return;
                }
            }
            AppTask::ProcessFilters(
                seqno,
                events,
                filters,
                rule_descriptions,
                http_descriptions,
            ) => {
                let filtered_events = events
                    .into_iter()
                    .filter(|event| filters.iter().all(|f| f.apply(event)))
                    .collect::<Vec<_>>();

                let filtered_stats =
                    calc_summary(&filtered_events, &rule_descriptions, &http_descriptions);

                if tx
                    .send(AppEvent::ProcessedFilters(
                        seqno,
                        filtered_events,
                        filtered_stats,
                    ))
                    .is_err()
                {
                    /* MainApp is dead */
                    return;
                }
            }
        }
    }
}

/// Introspection for ModSecurity log files
#[derive(Parser)]
#[command(version, about, author, long_about = None)]
struct Args {
    /// Log files to analyze
    files: Option<Vec<PathBuf>>,
}
fn main() -> io::Result<()> {
    let args = Args::parse();

    let mut app = MainApp::new(args.files);

    let mut terminal = ratatui::init();

    let app_result = app.run(&mut terminal);
    ratatui::restore();
    app_result
}
