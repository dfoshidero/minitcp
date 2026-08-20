//! The terminal UI: three panes over the same stack the CLI runs.
//!
//!   buffer  scrollback for one pane
//!   child   the `minitcp stack` and `tcpdump` processes it runs
//!   app     the lab's state and how output reaches it
//!   keys    what each keystroke does
//!   draw    turning that state into a screen
//!
//! The UI implements no protocol logic. It shells out to the same commands a
//! user could type, so every pane shows what those commands printed.

mod app;
mod buffer;
mod child;
mod draw;
mod keys;

use std::io::IsTerminal;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crossterm::event::{self, Event};
use ratatui::DefaultTerminal;

use crate::cli::Config;

use app::Lab;
use child::{SHUTDOWN_REQUESTED, install_signal_handlers};
use draw::draw;

fn ui_loop(terminal: &mut DefaultTerminal, lab: &mut Lab) -> std::io::Result<()> {
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            break;
        }
        lab.drain_msgs();
        lab.refresh_status();
        terminal.draw(|f| draw(f, lab))?;

        if event::poll(Duration::from_millis(80))? {
            match event::read()? {
                Event::Key(key) => {
                    if lab.handle_key(key) {
                        break;
                    }
                }
                Event::Mouse(m) => {
                    use crossterm::event::MouseEventKind;
                    match m.kind {
                        MouseEventKind::ScrollUp => lab.focused_buf_mut().scroll_up(3),
                        MouseEventKind::ScrollDown => lab.focused_buf_mut().scroll_down(3),
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub fn run_lab(cfg: Config) -> std::io::Result<()> {
    if !std::io::stdout().is_terminal() {
        return Err(std::io::Error::other(
            "run needs a terminal; use `minitcp stack` for piped output",
        ));
    }
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    install_signal_handlers().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("cannot install terminal signal handlers: {error}"),
        )
    })?;
    let mut lab = Lab::start(cfg)?;
    let mut terminal = ratatui::try_init().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("cannot initialize terminal UI: {error}"),
        )
    })?;
    let result = ui_loop(&mut terminal, &mut lab);
    if let Err(error) = ratatui::try_restore() {
        crate::log::status::warn(format!("could not fully restore terminal: {error}"));
    }
    lab.stack.kill();
    lab.dump.kill();
    if let Some(mut process) = lab.action_process.take() {
        process.kill();
    }
    result
}
