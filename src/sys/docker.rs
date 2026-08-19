// The TAP sidecar: a container that owns the real TAP so macOS (and any host
// without /dev/net/tun) can still run the lab.
//
// Everything in here is about the *container*. What goes on the wire once it is
// running belongs to `interface::fwd`, and creating a TAP directly on this
// machine belongs to `sys::tapdev`.

use std::io;
use std::thread;
use std::time::{Duration, Instant};

use crate::cli::Config;
use crate::interface::fwd::DEFAULT_FWD;
use crate::sys::process::{self, AllowedFailure};

pub(crate) const CONTAINER: &str = "minitcp-tap";
const IMAGE_REPO: &str = "ghcr.io/dfoshidero/minitcp";

const READY_TIMEOUT: Duration = Duration::from_secs(90);
const READY_INTERVAL: Duration = Duration::from_millis(200);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const RUN_TIMEOUT: Duration = Duration::from_secs(120);
const RUN_ATTEMPTS: usize = 3;

/// What Docker looks like from here, before we ask it to do anything.
///
/// The three cases lead to genuinely different advice, which is why they are
/// kept apart: `Missing` means Docker is not installed (fine on Linux, fatal
/// elsewhere), while `Unavailable` means it is installed but not answering —
/// usually Docker Desktop simply is not started.
pub enum State {
    Ready,
    Missing,
    Unavailable(String),
}

/// Which sidecar image to run, and how eagerly to re-pull it.
///
/// The sidecar is not an interchangeable helper: the host stack and the bridge
/// inside it speak a private wire format (length-prefixed Ethernet frames) that
/// is free to change between releases. `:latest` moves whenever a release is
/// published, so a host binary installed months ago could find itself talking
/// to an image built yesterday. Asking for the image that matches *this* binary
/// removes the question entirely.
///
/// The pull policy follows from the tag. A version tag is immutable, so once we
/// have it there is nothing to re-check — `missing` avoids a registry round trip
/// on every `tap up`. `latest` is mutable by definition, so it must be `always`.
fn image_and_pull_policy() -> (String, &'static str) {
    let release = env!("MINITCP_RELEASE").trim_start_matches('v');
    if release.is_empty() || release == "0.0.0" {
        return (format!("{IMAGE_REPO}:latest"), "always");
    }
    (format!("{IMAGE_REPO}:{release}"), "missing")
}

pub fn state() -> io::Result<State> {
    match process::output_timeout("docker", &["info"], COMMAND_TIMEOUT) {
        Ok(output) if output.status.success() => Ok(State::Ready),
        Ok(output) => {
            let detail = process::output_detail(&output);
            let detail = if detail.is_empty() {
                "docker info exited unsuccessfully".into()
            } else {
                detail
            };
            Ok(State::Unavailable(detail))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(State::Missing),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("cannot check Docker: {error}"),
        )),
    }
}

/// Start the sidecar if it is not already up, then wait until it is listening.
pub fn up(cfg: &Config) -> io::Result<()> {
    if !container_running()? {
        remove_quietly();

        let (image, pull) = image_and_pull_policy();
        let mut error = start_container(cfg, &image, pull).err();

        // A version-pinned image may simply not have been published — a build
        // straight from `main` names a version that only exists once it is
        // released. That is not the user's problem to solve, so fall back to
        // `:latest` and say plainly what happened.
        if error.as_ref().is_some_and(is_missing_image) && !image.ends_with(":latest") {
            crate::log::status::warn(format!(
                "{image} has not been published; falling back to :latest"
            ));
            remove_quietly();
            error = start_container(cfg, &format!("{IMAGE_REPO}:latest"), "always").err();
        }

        if let Some(error) = error {
            dump_logs();
            return Err(io::Error::new(
                error.kind(),
                format!("TAP sidecar failed to start: {error}"),
            ));
        }
    }

    wait_until_listening(cfg)?;
    crate::log::status::ok(format!(
        "TAP sidecar up; Linux  {} on {}  (host stack: {})",
        cfg.linux_addr,
        cfg.iface,
        cfg.fwd_addr()
    ));
    Ok(())
}

/// Remove the sidecar. `Ok(false)` means there was nothing to remove, which
/// leaves the caller free to go looking for a local TAP instead.
pub fn down() -> io::Result<bool> {
    let args = ["rm", "-f", CONTAINER];
    let output = process::output_timeout("docker", &args, COMMAND_TIMEOUT)?;
    if output.status.success() {
        crate::log::status::ok(format!("stopped {CONTAINER}"));
        return Ok(true);
    }
    process::check_output("docker", &args, output, AllowedFailure::DoesNotExist)?;
    Ok(false)
}

/// `docker run` the sidecar, retrying a few times.
///
/// The retries are for the first run on a slow connection: pulling the image
/// can outlast a single attempt, and a partly-pulled image leaves the container
/// name taken, which is why each retry removes it first.
fn start_container(cfg: &Config, image: &str, pull: &str) -> io::Result<()> {
    let port = DEFAULT_FWD.split(':').next_back().unwrap_or("7946");
    let args = vec![
        "run".to_string(),
        "-d".into(),
        "--name".into(),
        CONTAINER.into(),
        // The bridge creates a TAP, which needs root plus the two capabilities
        // below and access to the tun driver. It is otherwise unprivileged.
        "-u".into(),
        "0".into(),
        "--pull".into(),
        pull.into(),
        "--cap-add=NET_ADMIN".into(),
        "--cap-add=NET_RAW".into(),
        "--device=/dev/net/tun".into(),
        // Bound to loopback: the bridge speaks raw Ethernet frames with no
        // authentication, so it must not be reachable from the network.
        "-p".into(),
        format!("127.0.0.1:{port}:{port}"),
        image.into(),
        "bridge".into(),
        "--iface".into(),
        cfg.iface.clone(),
        "--linux-addr".into(),
        cfg.linux_addr.to_string(),
        // Inside the container this is the whole world, and the port publishing
        // above is what actually limits who can reach it.
        "--listen".into(),
        format!("0.0.0.0:{port}"),
    ];
    let refs: Vec<_> = args.iter().map(String::as_str).collect();

    let mut last_error = None;
    for attempt in 1..=RUN_ATTEMPTS {
        match process::output_timeout("docker", &refs, RUN_TIMEOUT) {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                last_error =
                    process::check_output("docker", &refs, output, AllowedFailure::None).err();
            }
            Err(error) => last_error = Some(error),
        }
        // A missing image will not appear on a retry, so stop wasting the
        // user's time and let the caller fall back instead.
        if last_error.as_ref().is_some_and(is_missing_image) {
            break;
        }
        if attempt < RUN_ATTEMPTS {
            crate::log::status::warn(format!(
                "TAP sidecar start failed; retrying ({attempt}/{RUN_ATTEMPTS})"
            ));
            remove_quietly();
            thread::sleep(Duration::from_secs(1));
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("docker run failed for an unknown reason")))
}

/// Did this failure mean "that image tag does not exist", as opposed to some
/// transient problem worth retrying?
fn is_missing_image(error: &io::Error) -> bool {
    let detail = error.to_string().to_ascii_lowercase();
    detail.contains("manifest unknown")
        || detail.contains("not found")
        || detail.contains("no such image")
        || detail.contains("manifest for")
}

/// A started container is not a ready one: the bridge inside it still has to
/// create its TAP and bind the port. Poll the port rather than guessing.
fn wait_until_listening(cfg: &Config) -> io::Result<()> {
    let addr = cfg.fwd_addr();
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if crate::interface::fwd::probe(&addr, READY_INTERVAL).is_ok() {
            return Ok(());
        }
        if !container_running()? {
            dump_logs();
            return Err(io::Error::other(
                "TAP sidecar exited before it was listening",
            ));
        }
        if Instant::now() >= deadline {
            dump_logs();
            return Err(io::Error::other(format!(
                "TAP sidecar did not accept {addr} within {}s",
                READY_TIMEOUT.as_secs()
            )));
        }
        thread::sleep(READY_INTERVAL);
    }
}

fn container_running() -> io::Result<bool> {
    let args = ["inspect", "-f", "{{.State.Running}}", CONTAINER];
    let output = process::output_timeout("docker", &args, COMMAND_TIMEOUT)?;
    if !output.status.success() {
        let detail = process::output_detail(&output);
        if detail.to_ascii_lowercase().contains("no such object") {
            return Ok(false);
        }
        return process::check_output("docker", &args, output, AllowedFailure::None)
            .map(|()| false);
    }
    let state = String::from_utf8(output.stdout).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Docker returned invalid container state: {error}"),
        )
    })?;
    Ok(state.trim() == "true")
}

fn remove_quietly() {
    let _ = process::output_timeout("docker", &["rm", "-f", CONTAINER], COMMAND_TIMEOUT);
}

/// When the sidecar will not start, the reason is almost always in its own
/// logs, not in what `docker run` printed. Show them rather than make the user
/// go and find them.
fn dump_logs() {
    match process::output_timeout("docker", &["logs", CONTAINER], COMMAND_TIMEOUT) {
        Ok(out) => {
            crate::log::status::info(format!("--- docker logs {CONTAINER} ---"));
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            if text.trim().is_empty() {
                let _ = crate::log::write_stderr("(no container logs)\n");
            } else {
                if !text.ends_with('\n') {
                    text.push('\n');
                }
                let _ = crate::log::write_stderr(&text);
            }
            crate::log::status::info("--- end docker logs ---");
        }
        Err(error) => crate::log::status::warn(format!(
            "could not read Docker logs for {CONTAINER}: {error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sidecar_matches_the_binary_that_launched_it() {
        let (image, pull) = image_and_pull_policy();
        assert!(image.starts_with(IMAGE_REPO), "{image}");

        let tag = image.rsplit(':').next().unwrap();
        if tag == "latest" {
            // A mutable tag has to be re-checked every time, or the sidecar
            // silently stays on whatever was pulled months ago.
            assert_eq!(pull, "always");
        } else {
            // A version tag is immutable, so re-pulling it can only ever
            // return the same bytes — an avoidable round trip on every start.
            assert_eq!(tag, env!("MINITCP_RELEASE").trim_start_matches('v'));
            assert_eq!(pull, "missing");
        }
    }

    #[test]
    fn an_unpublished_tag_is_recognised_so_we_can_fall_back() {
        // Docker's exact wording differs between daemon versions and
        // registries; these are the forms seen in practice.
        for detail in [
            "manifest unknown",
            "manifest for ghcr.io/dfoshidero/minitcp:9.9.9 not found",
            "Error response from daemon: No such image: minitcp:9.9.9",
        ] {
            assert!(is_missing_image(&io::Error::other(detail)), "{detail}");
        }
    }

    #[test]
    fn an_ordinary_failure_is_not_mistaken_for_a_missing_image() {
        // Retrying is right for these; falling back to :latest is not.
        for detail in [
            "Cannot connect to the Docker daemon",
            "port is already allocated",
            "operation timed out",
        ] {
            assert!(!is_missing_image(&io::Error::other(detail)), "{detail}");
        }
    }
}
