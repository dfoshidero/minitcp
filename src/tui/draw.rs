// Turning the lab's state into a screen.
//
// Nothing here mutates: `draw` reads `Lab` and emits widgets. Colour carries
// meaning — green arrived, cyan sent, red a problem — so direction of traffic
// is legible without reading the words.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};

use super::app::{Lab, Pane};
use super::buffer::Buffer;
use super::child::CaptureHost;

pub(super) fn style_line(text: &str) -> Line<'_> {
    let lower = text.to_ascii_lowercase();
    if text.starts_with("minitcp:") {
        let color = if lower.starts_with("minitcp: error:") {
            Color::Red
        } else if lower.starts_with("minitcp: warning:") {
            Color::Yellow
        } else {
            Color::LightBlue
        };
        return Line::from(Span::styled(text.to_string(), Style::default().fg(color)));
    }
    if lower.contains("error") || lower.contains("failed") || lower.contains("bad ") {
        return Line::from(Span::styled(
            text.to_string(),
            Style::default().fg(Color::Red),
        ));
    }
    if text.starts_with("$ ") {
        return Line::from(Span::styled(
            text.to_string(),
            Style::default().fg(Color::Green),
        ));
    }
    for (tag, color) in [
        ("[DROP]", Color::Red),
        ("[OUT]", Color::Green),
        ("[IN]", Color::Cyan),
        ("[..]", Color::DarkGray),
    ] {
        if let Some(at) = text.find(tag) {
            let gray = Style::default().fg(Color::Gray);
            return Line::from(vec![
                Span::styled(text[..at].to_string(), gray),
                Span::styled(
                    tag.to_string(),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(text[at + tag.len()..].to_string(), gray),
            ]);
        }
    }
    let color = if lower.contains("icmp") || lower.contains(" echo ") {
        Color::Cyan
    } else if lower.contains("arp") {
        Color::Yellow
    } else {
        Color::Gray
    };
    Line::from(Span::styled(text.to_string(), Style::default().fg(color)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PaneRole {
    MiniTcpCore,
    ExternalTool,
}

pub(super) fn pane_block(title: String, focused: bool, role: PaneRole) -> Block<'static> {
    let (border_color, title_color, background) = match (role, focused) {
        (PaneRole::MiniTcpCore, true) => (Color::LightCyan, Color::Black, Color::Rgb(3, 20, 36)),
        (PaneRole::MiniTcpCore, false) => (Color::Blue, Color::LightCyan, Color::Rgb(3, 15, 28)),
        (PaneRole::ExternalTool, true) => {
            (Color::LightYellow, Color::Black, Color::Rgb(12, 18, 24))
        }
        (PaneRole::ExternalTool, false) => (Color::DarkGray, Color::Gray, Color::Black),
    };
    let title = if focused {
        format!(" ▶ {title} ")
    } else {
        format!(" {title} ")
    };
    let title_style = if focused {
        Style::default()
            .fg(title_color)
            .bg(border_color)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(title_color)
            .add_modifier(Modifier::BOLD)
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(if focused {
            BorderType::Double
        } else {
            BorderType::Plain
        })
        .title(title)
        .title_style(title_style)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(background).fg(Color::Gray))
}

pub(super) fn draw(frame: &mut Frame, lab: &mut Lab) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Ratio(2, 3),
            Constraint::Ratio(1, 3),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let ours = lab.cfg.addr.to_string();
    let tap = if lab.tap_up { "UP" } else { "DOWN" };
    let tap_color = if lab.tap_up { Color::Green } else { Color::Red };
    let stack_st = if lab.stack_alive { "run" } else { "off" };
    let dump_st = if lab.dump_alive { "run" } else { "off" };
    let status = Line::from(vec![
        Span::styled(
            " MiniTCP ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" {} ", lab.cfg.iface)),
        Span::styled(
            tap,
            Style::default().fg(tap_color).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::raw(lab.tap_addr.as_str()),
        Span::raw("  ↔  "),
        Span::raw(ours),
        Span::raw("   Core:"),
        Span::styled(
            stack_st,
            Style::default().fg(if lab.stack_alive {
                Color::Green
            } else {
                Color::Red
            }),
        ),
        Span::raw("  log:"),
        Span::styled(
            if lab.verbose { "verbose" } else { "quiet" },
            Style::default().fg(if lab.verbose {
                Color::Cyan
            } else {
                Color::Gray
            }),
        ),
        Span::raw(format!(
            "  icmp {}/{}  arp {}/{}",
            lab.icmp_in, lab.icmp_out, lab.arp_in, lab.arp_out
        )),
        Span::raw("  Capture:"),
        Span::styled(
            format!("{}:{}", dump_st, lab.filter.label()),
            Style::default().fg(if lab.dump_alive {
                Color::Yellow
            } else {
                Color::Red
            }),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(status).style(Style::default().bg(Color::DarkGray)),
        layout[0],
    );

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(layout[1]);
    let stack_focused = lab.focus == Pane::Stack;
    let dump_focused = lab.focus == Pane::Dump;
    let actions_focused = lab.focus == Pane::Actions;

    render_term(
        frame,
        top[0],
        "1 MiniTCP Core",
        &mut lab.stack_buf,
        stack_focused,
        PaneRole::MiniTcpCore,
    );
    // Name where the capture runs: the same screen can be sniffing a different
    // kernel on someone else's machine.
    let capture_title = match lab.capture {
        CaptureHost::Local => "2 TAP Capture (this host)",
        CaptureHost::Sidecar => "2 TAP Capture (sidecar)",
    };
    render_term(
        frame,
        top[1],
        capture_title,
        &mut lab.dump_buf,
        dump_focused,
        PaneRole::ExternalTool,
    );
    render_term(
        frame,
        layout[2],
        "3 External Tools",
        &mut lab.action_buf,
        actions_focused,
        PaneRole::ExternalTool,
    );

    let footer = match &lab.command_input {
        Some(input) => Line::from(vec![
            Span::styled(
                " COMMAND › ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" {input}")),
            Span::styled("█", Style::default().fg(Color::Cyan)),
            Span::styled(
                "  Enter run · Esc cancel",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        None => Line::from(vec![
            key("tab/1-3", "focus"),
            key("↑↓", "scroll"),
            key("a", "live"),
            key(":", "command"),
            key("p", "ping"),
            key("n", "neigh"),
            key("f", "flush"),
            key("d", "filter"),
            key("v", if lab.verbose { "quiet" } else { "verbose" }),
            key("q", "quit"),
        ]),
    };
    frame.render_widget(Paragraph::new(footer), layout[3]);
}

pub(super) fn key<'a>(k: &'a str, label: &'a str) -> Span<'a> {
    Span::from(format!(" <{k}> {label}  ")).style(Style::default().fg(Color::Yellow))
}

pub(super) fn render_term(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    buf: &mut Buffer,
    focused: bool,
    role: PaneRole,
) {
    let inner_h = area.height.saturating_sub(2) as usize;
    let visible = buf.visible(inner_h);
    let lines: Vec<Line> = visible.iter().map(|s| style_line(s)).collect();
    let title = if buf.auto_follow {
        title.to_string()
    } else {
        format!("{title} · PAUSED")
    };
    let mut widget = Paragraph::new(lines).block(pane_block(title, focused, role));
    if role != PaneRole::MiniTcpCore {
        widget = widget.wrap(Wrap { trim: false });
    }
    frame.render_widget(widget, area);
}
