// Check GitHub Releases for a newer host binary. Fail open; never block the lab.

use std::io::IsTerminal;
use std::time::{Duration, SystemTime};

/// How long a *successful* check is trusted for.
const CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// How long to wait after a check that never got an answer — much shorter,
/// since the usual cause is a laptop that was briefly offline.
const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);
pub const REPO: &str = "dfoshidero/minitcp";

/// The one-liner the README, `--help` and the update nag all point at.
pub const INSTALL_URL: &str =
    "https://github.com/dfoshidero/minitcp/releases/latest/download/install.sh";

pub fn nag_if_outdated() {
    if std::env::var_os("MINITCP_NO_UPDATE_CHECK").is_some() {
        return;
    }
    if !std::io::stderr().is_terminal() {
        return;
    }
    if recently_checked() {
        return;
    }
    // Record the attempt before making it: an unreachable network costs a
    // two-second timeout, which nobody should pay on every command. It also
    // means a crash mid-request still counts as an attempt.
    mark_checked(Outcome::Failed);
    let Some(latest) = fetch_latest() else {
        return;
    };
    mark_checked(Outcome::Succeeded);
    let current = env!("MINITCP_RELEASE").trim_start_matches('v');
    let latest = latest.trim_start_matches('v');
    if version_newer(latest, current) {
        crate::log::status::info(format!(
            "minitcp {latest} is available (you have {current})"
        ));
        crate::log::status::info(format!("Update: curl -fsSL {INSTALL_URL} | sh"));
    }
}

fn cache_path() -> Option<std::path::PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        return Some(
            std::path::PathBuf::from(xdg)
                .join("minitcp")
                .join("update-check"),
        );
    }
    let home = std::path::PathBuf::from(std::env::var_os("HOME")?);
    #[cfg(target_os = "macos")]
    {
        Some(
            home.join("Library")
                .join("Caches")
                .join("minitcp")
                .join("update-check"),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(home.join(".cache").join("minitcp").join("update-check"))
    }
}

/// Whether the last check actually reached GitHub.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Succeeded,
    Failed,
}

impl Outcome {
    /// What the marker file says, and how long it silences the next check for.
    fn marker(self) -> (&'static [u8], Duration) {
        match self {
            Self::Succeeded => (b"ok", CACHE_MAX_AGE),
            Self::Failed => (b"failed", RETRY_AFTER),
        }
    }

    fn from_marker(bytes: &[u8]) -> Self {
        if bytes.starts_with(b"ok") {
            Self::Succeeded
        } else {
            Self::Failed
        }
    }
}

/// Have we checked recently enough to leave it alone? Every branch answers
/// "no" on any doubt — checking again is free, never checking is not.
fn recently_checked() -> bool {
    let Some(path) = cache_path() else {
        return false;
    };
    let Ok(contents) = std::fs::read(&path) else {
        return false;
    };
    let Ok(modified) = std::fs::metadata(&path).and_then(|meta| meta.modified()) else {
        return false;
    };
    let (_, max_age) = Outcome::from_marker(&contents).marker();
    SystemTime::now()
        .duration_since(modified)
        .map(|age| age < max_age)
        .unwrap_or(false)
}

fn mark_checked(outcome: Outcome) {
    let Some(path) = cache_path() else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let (marker, _) = outcome.marker();
    let _ = std::fs::write(path, marker);
}

fn fetch_latest() -> Option<String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = ureq::get(&url)
        .set("User-Agent", "minitcp")
        .timeout(std::time::Duration::from_secs(2))
        .call()
        .ok()?
        .into_string()
        .ok()?;
    parse_tag_name(&body)
}

fn parse_tag_name(json: &str) -> Option<String> {
    let key = "\"tag_name\"";
    let i = json.find(key)?;
    let rest = &json[i + key.len()..];
    let start = rest.find('"')? + 1;
    let end = rest[start..].find('"')?;
    Some(rest[start..start + end].to_string())
}

fn version_newer(latest: &str, current: &str) -> bool {
    parse_semver(latest) > parse_semver(current)
}

fn parse_semver(s: &str) -> (u64, u64, u64) {
    let mut parts = s.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch = parts
        .next()
        .and_then(|p| p.split('-').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    (major, minor, patch)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_install_url_points_at_this_repo() {
        assert!(INSTALL_URL.contains(REPO), "{INSTALL_URL}");
    }

    use super::*;

    #[test]
    fn a_failed_check_is_retried_much_sooner_than_a_successful_one() {
        let (ok_marker, ok_age) = Outcome::Succeeded.marker();
        let (failed_marker, failed_age) = Outcome::Failed.marker();
        assert!(
            failed_age < ok_age,
            "a check that never reached GitHub must not silence the next one for as long"
        );
        // The two markers have to be distinguishable, or the outcome is lost.
        assert_ne!(ok_marker, failed_marker);
    }

    #[test]
    fn a_marker_round_trips_through_the_cache_file() {
        for outcome in [Outcome::Succeeded, Outcome::Failed] {
            let (marker, _) = outcome.marker();
            assert!(Outcome::from_marker(marker) == outcome);
        }
    }

    #[test]
    fn an_unreadable_marker_is_treated_as_a_failed_check() {
        // Old versions wrote an empty file. Assuming failure re-checks sooner,
        // which is the harmless direction to be wrong in.
        assert!(Outcome::from_marker(b"") == Outcome::Failed);
        assert!(Outcome::from_marker(b"\xff\xfe") == Outcome::Failed);
    }

    #[test]
    fn parse_tag_from_github_json() {
        let json = r#"{"tag_name":"v1.2.3","name":"1.2.3"}"#;
        assert_eq!(parse_tag_name(json).as_deref(), Some("v1.2.3"));
    }

    #[test]
    fn newer_patch() {
        assert!(version_newer("1.2.3", "1.2.2"));
        assert!(!version_newer("1.1.0", "1.1.0"));
        assert!(!version_newer("1.0.9", "1.1.0"));
    }
}
