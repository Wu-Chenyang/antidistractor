//! Cross-platform TUI for Antidistractor.
//!
//! Uses ratatui + crossterm (both support Linux and macOS).
//! The blocker backend is abstracted via BlockerBackend enum to support
//! both Linux eBPF and macOS PF implementations.

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, List, ListItem, Paragraph, Clear},
    Frame, Terminal,
};
use std::{error::Error, io};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Platform-agnostic blocker backend.
/// Abstracts the difference between Linux eBPF and macOS PF.
pub enum BlockerBackend {
    #[cfg(target_os = "linux")]
    Ebpf(crate::ebpf::EbpfManager),
    #[cfg(target_os = "macos")]
    Pf(crate::macos::PfBlocker),
    /// No backend available (e.g., insufficient permissions or init failed)
    None,
}

impl BlockerBackend {
    /// Add a domain to the blocklist.
    pub fn add_domain(&mut self, domain: &str) -> Result<(), String> {
        match self {
            #[cfg(target_os = "linux")]
            BlockerBackend::Ebpf(mgr) => mgr.add_domain(domain).map_err(|e| e.to_string()),
            #[cfg(target_os = "macos")]
            BlockerBackend::Pf(pf) => pf.add_domain(domain).map_err(|e| e.to_string()),
            BlockerBackend::None => Err("No blocker backend available".to_string()),
        }
    }

    /// Remove a domain from the blocklist.
    pub fn remove_domain(&mut self, domain: &str) -> Result<(), String> {
        match self {
            #[cfg(target_os = "linux")]
            BlockerBackend::Ebpf(mgr) => mgr.remove_domain(domain).map_err(|e| e.to_string()),
            #[cfg(target_os = "macos")]
            BlockerBackend::Pf(pf) => pf.remove_domain(domain).map_err(|e| e.to_string()),
            BlockerBackend::None => Err("No blocker backend available".to_string()),
        }
    }

    /// Return a human-readable description of the backend.
    pub fn backend_name(&self) -> &'static str {
        match self {
            #[cfg(target_os = "linux")]
            BlockerBackend::Ebpf(_) => "eBPF TC Classifier",
            #[cfg(target_os = "macos")]
            BlockerBackend::Pf(_) => "PF Firewall + /etc/hosts",
            BlockerBackend::None => "Unavailable",
        }
    }

    /// Whether the backend is functional.
    #[allow(dead_code)]
    pub fn is_available(&self) -> bool {
        !matches!(self, BlockerBackend::None)
    }
}

pub enum InputMode { Normal, Editing }

pub struct App {
    pub protection_active: bool,
    pub blocklist: Vec<String>,
    pub logs: Vec<String>,
    pub should_quit: bool,
    pub input: String,
    pub input_mode: InputMode,
    pub backend: BlockerBackend,
    pub log_rx: mpsc::UnboundedReceiver<String>,
}

impl App {
    pub fn new(mut backend: BlockerBackend, log_rx: mpsc::UnboundedReceiver<String>) -> App {
        let blocklist = vec!["www.bilibili.com".to_string(), "bilibili.com".to_string()];

        // Sync initial list to blocker
        for domain in &blocklist {
            if let Err(e) = backend.add_domain(domain) {
                log::warn!("Failed to add initial domain '{}': {}", domain, e);
            }
        }

        App {
            protection_active: true,
            blocklist,
            logs: vec!["System started.".to_string()],
            should_quit: false,
            input: String::new(),
            input_mode: InputMode::Normal,
            backend,
            log_rx,
        }
    }

    pub fn add_domain(&mut self, domain: String) {
        match self.backend.add_domain(&domain) {
            Ok(()) => {
                self.blocklist.push(domain);
            }
            Err(e) => {
                self.logs.push(format!("Error: {}", e));
            }
        }
    }

    pub fn remove_domain(&mut self) {
        if let Some(domain) = self.blocklist.pop() {
            if let Err(e) = self.backend.remove_domain(&domain) {
                self.logs.push(format!("Error removing '{}': {}", domain, e));
            }
        }
    }

    pub fn update_logs(&mut self) {
        while let Ok(log) = self.log_rx.try_recv() {
            self.logs.push(log);
            if self.logs.len() > 100 { self.logs.remove(0); }
        }
    }
}

pub async fn run_ui(
    backend: Option<BlockerBackend>,
    log_rx: mpsc::UnboundedReceiver<String>,
) -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend_term = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend_term)?;

    let blocker_backend = backend.unwrap_or(BlockerBackend::None);
    let mut app = App::new(blocker_backend, log_rx);
    let res = run_app(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(err) = res { println!("{:?}", err) }
    Ok(())
}

async fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        app.update_logs();
        terminal.draw(|f| ui(f, app))?;

        let timeout = tick_rate.checked_sub(last_tick.elapsed()).unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match app.input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') => app.should_quit = true,
                        KeyCode::Char('a') => app.input_mode = InputMode::Editing,
                        KeyCode::Char('d') => app.remove_domain(),
                        KeyCode::Char('p') => app.protection_active = !app.protection_active,
                        _ => {}
                    },
                    InputMode::Editing => match key.code {
                        KeyCode::Enter => {
                            let domain = app.input.drain(..).collect::<String>();
                            if !domain.is_empty() {
                                app.add_domain(domain);
                            }
                            app.input_mode = InputMode::Normal;
                        }
                        KeyCode::Char(c) => app.input.push(c),
                        KeyCode::Backspace => { app.input.pop(); }
                        KeyCode::Esc => app.input_mode = InputMode::Normal,
                        _ => {}
                    },
                }
            }
        }
        if last_tick.elapsed() >= tick_rate { last_tick = Instant::now(); }
        if app.should_quit { return Ok(()); }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(15),
            Constraint::Length(3),
        ].as_ref())
        .split(f.size());

    let title_style = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    let status = if app.protection_active { "ACTIVE" } else { "PAUSED" };
    let status_color = if app.protection_active { Color::Green } else { Color::Red };

    // Show backend name in title
    let backend_info = app.backend.backend_name();
    let title_text = format!(
        "Antidistractor ({}) [{}]",
        backend_info, status
    );
    let title = Paragraph::new(Span::styled(title_text, title_style.fg(status_color)))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let blocklist = List::new(
        app.blocklist.iter()
            .map(|i| ListItem::new(i.as_str()))
            .collect::<Vec<_>>()
    )
    .block(Block::default().borders(Borders::ALL).title("Blocklist (Active Domains)"));
    f.render_widget(blocklist, chunks[1]);

    let log_title = if cfg!(target_os = "linux") {
        "Kernel / System Logs"
    } else {
        "System Logs"
    };
    let logs = List::new(
        app.logs.iter().rev()
            .map(|l| ListItem::new(l.as_str()))
            .collect::<Vec<_>>()
    )
    .block(Block::default().borders(Borders::ALL).title(log_title));
    f.render_widget(logs, chunks[2]);

    let help = Paragraph::new("q: Quit | a: Add Domain | d: Delete Last | p: Toggle Protection")
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(help, chunks[3]);

    if let InputMode::Editing = app.input_mode {
        let area = centered_rect(60, 20, f.size());
        f.render_widget(Clear, area);
        let input = Paragraph::new(app.input.as_str())
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Enter Domain to Block"));
        f.render_widget(input, area);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ].as_ref())
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ].as_ref())
        .split(popup_layout[1])[1]
}
