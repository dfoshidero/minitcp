// What a bad command line produces.
//
// A `ParseError` carries what was wrong and the smallest piece of usage text
// that would have prevented it. Full `--help` is for people who asked for it.

use super::usage::{TRY_HELP, flag_usage};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub usage: Option<String>,
    /// What minitcp exits with. 2 says the command line was wrong, which is
    /// the usual case; writing minitcp.toml can fail for reasons the user did
    /// not type, and that is an ordinary failure (1).
    exit_code: i32,
}

impl ParseError {
    pub(crate) fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            usage: Some(TRY_HELP.into()),
            exit_code: 2,
        }
    }

    pub(crate) fn with_usage(message: impl Into<String>, usage: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            usage: Some(usage.into()),
            exit_code: 2,
        }
    }

    /// The same error, reported as a failure to do the work rather than as a
    /// misuse of the command line.
    pub(crate) fn into_failure(self) -> Self {
        Self {
            exit_code: 1,
            ..self
        }
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
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

pub(crate) fn missing_value(flag: &str) -> ParseError {
    ParseError::with_usage(format!("{flag} needs a value"), flag_usage(flag))
}
