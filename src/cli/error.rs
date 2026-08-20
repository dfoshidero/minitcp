// What a bad command line produces.
//
// A `ParseError` carries what was wrong and the smallest piece of usage text
// that would have prevented it. Full `--help` is for people who asked for it.

use super::usage::{TRY_HELP, flag_usage};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub usage: Option<String>,
}

impl ParseError {
    pub(crate) fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            usage: Some(TRY_HELP.into()),
        }
    }

    pub(crate) fn with_usage(message: impl Into<String>, usage: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            usage: Some(usage.into()),
        }
    }

    /// Family help only — no `error:` prefix.
    pub(crate) fn usage_only(usage: impl Into<String>) -> Self {
        Self {
            message: String::new(),
            usage: Some(usage.into()),
        }
    }

    pub fn report(&self) -> String {
        match (&self.message.is_empty(), &self.usage) {
            (true, Some(usage)) => format!("{usage}\n"),
            (false, Some(usage)) => format!("error: {}\n\n{usage}\n", self.message),
            (false, None) => format!("error: {}\n\n{TRY_HELP}\n", self.message),
            (true, None) => format!("{TRY_HELP}\n"),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.report())
    }
}

impl From<String> for ParseError {
    fn from(message: String) -> Self {
        Self::msg(message)
    }
}

impl From<&str> for ParseError {
    fn from(message: &str) -> Self {
        Self::msg(message)
    }
}

pub(crate) fn missing_value(flag: &str) -> ParseError {
    ParseError::with_usage(format!("{flag} needs a value"), flag_usage(flag))
}
