// One scrollback pane's worth of text.
//
// Two ideas make this more than a Vec of strings. It is capped, so a lab left
// running overnight cannot eat memory. And it distinguishes *following* the
// output from *looking at* it: scroll up and new lines stop yanking the view
// away, which is the difference between being able to read what just happened
// and watching it scroll past.

use std::collections::VecDeque;

pub(super) const MAX_LINES: usize = 2000;

pub(super) struct Buffer {
    pub(super) lines: VecDeque<String>,
    /// Lines hidden at the bottom while looking through scrollback.
    pub(super) from_bottom: usize,
    pub(super) viewport_height: usize,
    pub(super) auto_follow: bool,
}

impl Buffer {
    pub(super) fn new() -> Self {
        Self {
            lines: VecDeque::new(),
            from_bottom: 0,
            viewport_height: 0,
            auto_follow: true,
        }
    }

    pub(super) fn push(&mut self, line: String) {
        self.lines.push_back(line);
        while self.lines.len() > MAX_LINES {
            self.lines.pop_front();
        }
        if self.auto_follow {
            self.from_bottom = 0;
        } else {
            let max = self.lines.len().saturating_sub(self.viewport_height);
            self.from_bottom = self.from_bottom.saturating_add(1).min(max);
        }
    }

    pub(super) fn push_output(&mut self, line: String, force_follow: bool) {
        if force_follow {
            self.follow();
        }
        self.push(line);
    }

    pub(super) fn clear(&mut self) {
        self.lines.clear();
        self.from_bottom = 0;
        self.auto_follow = true;
    }

    pub(super) fn scroll_up(&mut self, n: usize) {
        let max = self.lines.len().saturating_sub(self.viewport_height);
        self.from_bottom = (self.from_bottom + n).min(max);
        if self.from_bottom > 0 {
            self.auto_follow = false;
        }
    }

    pub(super) fn scroll_down(&mut self, n: usize) {
        self.from_bottom = self.from_bottom.saturating_sub(n);
        if self.from_bottom == 0 {
            self.auto_follow = true;
        }
    }

    pub(super) fn follow(&mut self) {
        self.from_bottom = 0;
        self.auto_follow = true;
    }

    pub(super) fn toggle_follow(&mut self) {
        if self.auto_follow {
            self.auto_follow = false;
        } else {
            self.follow();
        }
    }

    pub(super) fn page_size(&self) -> usize {
        self.viewport_height.saturating_sub(1).max(1)
    }

    pub(super) fn visible(&mut self, height: usize) -> Vec<String> {
        self.viewport_height = height;
        let max = self.lines.len().saturating_sub(height);
        self.from_bottom = self.from_bottom.min(max);
        if max == 0 {
            self.auto_follow = true;
        }
        if height == 0 || self.lines.is_empty() {
            return Vec::new();
        }
        let end = self.lines.len().saturating_sub(self.from_bottom);
        let start = end.saturating_sub(height);
        self.lines
            .iter()
            .skip(start)
            .take(end - start)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_scrolls_and_returns_to_latest_output() {
        let mut buffer = Buffer::new();
        for n in 1..=5 {
            buffer.push(n.to_string());
        }

        assert_eq!(buffer.visible(2), ["4", "5"]);
        buffer.scroll_up(2);
        assert_eq!(buffer.visible(2), ["2", "3"]);
        buffer.follow();
        assert_eq!(buffer.visible(2), ["4", "5"]);
    }

    #[test]
    fn paused_buffer_stays_put_until_live_follow_is_restored() {
        let mut buffer = Buffer::new();
        for n in 1..=5 {
            buffer.push(n.to_string());
        }

        assert_eq!(buffer.visible(2), ["4", "5"]);
        buffer.scroll_up(2);
        buffer.push("6".into());
        assert_eq!(buffer.visible(2), ["2", "3"]);

        buffer.push_output("7".into(), true);
        assert!(buffer.auto_follow);
        assert_eq!(buffer.visible(2), ["6", "7"]);
    }

    #[test]
    fn live_follow_can_be_paused_while_at_the_bottom() {
        let mut buffer = Buffer::new();
        for n in 1..=5 {
            buffer.push(n.to_string());
        }

        assert_eq!(buffer.visible(2), ["4", "5"]);
        buffer.toggle_follow();
        buffer.push("6".into());
        assert!(!buffer.auto_follow);
        assert_eq!(buffer.visible(2), ["4", "5"]);
    }

    #[test]
    fn buffer_does_not_scroll_until_it_overflows_the_pane() {
        let mut buffer = Buffer::new();
        buffer.push("first".into());
        buffer.push("second".into());

        assert_eq!(buffer.visible(4), ["first", "second"]);
        buffer.scroll_up(5);
        assert_eq!(buffer.from_bottom, 0);
        assert_eq!(buffer.visible(4), ["first", "second"]);
    }

    #[test]
    fn buffer_clear_removes_scrollback() {
        let mut buffer = Buffer::new();
        buffer.push("packet".into());
        buffer.clear();
        assert!(buffer.visible(10).is_empty());
    }
}
