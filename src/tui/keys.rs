// What each keystroke does.
//
// One file, so the key map reads as a list and can be checked against the hint
// bar drawn at the bottom of the screen.

use std::thread;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::sys::docker::CONTAINER;

use super::app::{Lab, Pane, run_short};

impl Lab {
    pub(super) fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        if self.command_input.is_some() {
            match key.code {
                KeyCode::Esc => self.command_input = None,
                KeyCode::Enter => {
                    if let Some(command) = self.command_input.take() {
                        self.run_command(command);
                    }
                }
                KeyCode::Backspace => {
                    if let Some(input) = self.command_input.as_mut() {
                        input.pop();
                    }
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if let Some(input) = self.command_input.as_mut() {
                        input.push(character);
                    }
                }
                _ => {}
            }
            return false;
        }
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::Char('1') => self.focus = Pane::Stack,
            KeyCode::Char('2') => self.focus = Pane::Dump,
            KeyCode::Char('3') => self.focus = Pane::Actions,
            KeyCode::Char(':') => {
                self.focus = Pane::Actions;
                self.command_input = Some(String::new());
            }
            KeyCode::Char('p') => {
                let tx = self.tx.clone();
                let addr = self.cfg.addr.to_string();
                let sidecar = self.cfg.fwd.is_some();
                thread::spawn(move || {
                    if sidecar {
                        run_short(
                            &tx,
                            "docker",
                            &["exec", CONTAINER, "ping", "-c", "1", "-W", "1", &addr],
                        );
                    } else {
                        run_short(&tx, "ping", &["-c", "1", "-W", "1", &addr]);
                    }
                });
            }
            KeyCode::Char('n') => {
                let tx = self.tx.clone();
                let iface = self.cfg.iface.clone();
                let sidecar = self.cfg.fwd.is_some();
                thread::spawn(move || {
                    if sidecar {
                        run_short(
                            &tx,
                            "docker",
                            &["exec", CONTAINER, "ip", "neigh", "show", "dev", &iface],
                        );
                    } else {
                        run_short(&tx, "ip", &["neigh", "show", "dev", &iface]);
                    }
                });
            }
            KeyCode::Char('f') => {
                let tx = self.tx.clone();
                let iface = self.cfg.iface.clone();
                let sidecar = self.cfg.fwd.is_some();
                thread::spawn(move || {
                    if sidecar {
                        run_short(
                            &tx,
                            "docker",
                            &["exec", CONTAINER, "ip", "neigh", "flush", "dev", &iface],
                        );
                    } else {
                        run_short(&tx, "sudo", &["-n", "ip", "neigh", "flush", "dev", &iface]);
                    }
                });
            }
            KeyCode::Char('r') => self.restart_stack(),
            KeyCode::Char('v') => self.toggle_verbose(),
            KeyCode::Char('t') => self.restart_dump(),
            KeyCode::Char('d') => self.cycle_filter(),
            KeyCode::Char('c') => self.clear_focused(),
            KeyCode::Char('a') => self.focused_buf_mut().toggle_follow(),
            KeyCode::Up => self.focused_buf_mut().scroll_up(1),
            KeyCode::Down => self.focused_buf_mut().scroll_down(1),
            KeyCode::PageUp => {
                let page = self.focused_buf_mut().page_size();
                self.focused_buf_mut().scroll_up(page);
            }
            KeyCode::PageDown => {
                let page = self.focused_buf_mut().page_size();
                self.focused_buf_mut().scroll_down(page);
            }
            KeyCode::End => self.focused_buf_mut().follow(),
            _ => {}
        }
        false
    }
}
