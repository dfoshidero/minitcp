// Check GitHub Releases for a newer host binary. Fail open; never block the lab.

use std::io::IsTerminal;
use std::time::{Duration, SystemTime};

const CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const REPO: &str = "dfoshidero/minitcp";

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
    mark_checked();
    let Some(latest) = fetch_latest() else {
        return;
    };
    let current = env!("MINITCP_RELEASE").trim_start_matches('v');
    let latest = latest.trim_start_matches('v');
    if version_newer(latest, current) {
        crate::log::status::info(format!(
            "minitcp {latest} is available (you have {current})"
        ));
        crate::log::status::info(format!(
            "Update: curl -fsSL https://github.com/{REPO}/releases/latest/download/install.sh | sh"
        ));
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

fn recently_checked() -> bool {
    let Some(path) = cache_path() else {
        return false;
    };
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|d| d < CACHE_MAX_AGE)
        .unwrap_or(false)
}

fn mark_checked() {
    let Some(path) = cache_path() else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, b"");
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
    use super::*;

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
