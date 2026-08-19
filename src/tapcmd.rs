// Host helpers: start/stop the TAP sidecar (Docker) or local Linux TAP.

use std::io;
use std::thread;
use std::time::{Duration, Instant};

use crate::cli::Config;
use crate::interface::fwd::DEFAULT_FWD;
use crate::process::{self, AllowedFailure};

pub(crate) const CONTAINER: &str = "minitcp-tap";
const IMAGE: &str = "ghcr.io/dfoshidero/minitcp:latest";

const READY_TIMEOUT: Duration = Duration::from_secs(90);
const READY_INTERVAL: Duration = Duration::from_millis(200);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const DOCKER_RUN_TIMEOUT: Duration = Duration::from_secs(120);
const DOCKER_RUN_ATTEMPTS: usize = 3;

enum DockerState {
    Ready,
    Missing,
    Unavailable(String),
}

pub fn tap_up(cfg: &Config) -> io::Result<()> {
    match docker_state()? {
        DockerState::Ready => return docker_up(cfg),
        DockerState::Unavailable(detail) if !cfg!(target_os = "linux") => {
            return Err(io::Error::other(format!(
                "Docker is unavailable; start Docker Desktop and try again: {detail}"
            )));
        }
        DockerState::Unavailable(detail) => {
            crate::log::status::warn(format!(
                "Docker is unavailable ({detail}); using a local Linux TAP"
            ));
        }
        DockerState::Missing => {}
    }
    if cfg!(target_os = "linux") {
        return local_linux_up(cfg);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "docker not found; install Docker Desktop (or Docker Engine) for TAP",
    ))
}

pub fn tap_down(cfg: &Config) -> io::Result<()> {
    let docker = docker_state()?;
    if matches!(&docker, DockerState::Ready) {
        let output = process::output_timeout("docker", &["rm", "-f", CONTAINER], COMMAND_TIMEOUT)?;
        if output.status.success() {
            crate::log::status::ok(format!("stopped {CONTAINER}"));
            return Ok(());
        }
        process::check_output(
            "docker",
            &["rm", "-f", CONTAINER],
            output,
            AllowedFailure::DoesNotExist,
        )?;
    }
    if cfg!(target_os = "linux") {
        if let DockerState::Unavailable(detail) = docker {
            crate::log::status::warn(format!(
                "Docker is unavailable ({detail}); removing only the local Linux TAP"
            ));
        }
        process::run_sudo(
            &["ip", "link", "delete", &cfg.iface],
            AllowedFailure::DoesNotExist,
        )?;
        crate::log::status::ok(format!("removed {} if it existed", cfg.iface));
        return Ok(());
    }
    if let DockerState::Unavailable(detail) = docker {
        return Err(io::Error::other(format!(
            "Docker is unavailable, so the TAP sidecar could not be stopped: {detail}"
        )));
    }
    crate::log::status::info("TAP sidecar was not running");
    Ok(())
}

fn docker_state() -> io::Result<DockerState> {
    match process::output_timeout("docker", &["info"], COMMAND_TIMEOUT) {
        Ok(output) if output.status.success() => Ok(DockerState::Ready),
        Ok(output) => {
            let detail = process::output_detail(&output);
            let detail = if detail.is_empty() {
                "docker info exited unsuccessfully".into()
            } else {
                detail
            };
            Ok(DockerState::Unavailable(detail))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(DockerState::Missing),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("cannot check Docker: {error}"),
        )),
    }
}

fn docker_up(cfg: &Config) -> io::Result<()> {
    if !container_running()? {
        docker_rm_quiet();

        let port = DEFAULT_FWD.split(':').next_back().unwrap_or("7946");
        let args = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            CONTAINER.into(),
            "-u".into(),
            "0".into(),
            "--pull".into(),
            "always".into(),
            "--cap-add=NET_ADMIN".into(),
            "--cap-add=NET_RAW".into(),
            "--device=/dev/net/tun".into(),
            "-p".into(),
            format!("127.0.0.1:{port}:{port}"),
            IMAGE.into(),
            "bridge".into(),
            "--iface".into(),
            cfg.iface.clone(),
            "--linux-addr".into(),
            cfg.linux_addr.to_string(),
            "--listen".into(),
            format!("0.0.0.0:{port}"),
        ];
        let refs: Vec<_> = args.iter().map(String::as_str).collect();
        let mut last_error = None;
        for attempt in 1..=DOCKER_RUN_ATTEMPTS {
            match process::output_timeout("docker", &refs, DOCKER_RUN_TIMEOUT) {
                Ok(output) if output.status.success() => {
                    last_error = None;
                    break;
                }
                Ok(output) => {
                    last_error =
                        process::check_output("docker", &refs, output, AllowedFailure::None).err();
                }
                Err(error) => last_error = Some(error),
            }
            if attempt < DOCKER_RUN_ATTEMPTS {
                crate::log::status::warn(format!(
                    "TAP sidecar start failed; retrying ({attempt}/{DOCKER_RUN_ATTEMPTS})"
                ));
                docker_rm_quiet();
                thread::sleep(Duration::from_secs(1));
            }
        }
        if let Some(error) = last_error {
            dump_sidecar_logs();
            return Err(io::Error::new(
                error.kind(),
                format!("TAP sidecar failed to start: {error}"),
            ));
        }
    }

    wait_for_sidecar(cfg)?;
    crate::log::status::ok(format!(
        "TAP sidecar up; Linux  {} on {}  (host stack: {})",
        cfg.linux_addr,
        cfg.iface,
        cfg.fwd_addr()
    ));
    Ok(())
}

fn wait_for_sidecar(cfg: &Config) -> io::Result<()> {
    let addr = cfg.fwd_addr();
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if crate::interface::fwd::probe(&addr, READY_INTERVAL).is_ok() {
            return Ok(());
        }
        if !container_running()? {
            dump_sidecar_logs();
            return Err(io::Error::other(
                "TAP sidecar exited before it was listening",
            ));
        }
        if Instant::now() >= deadline {
            dump_sidecar_logs();
            return Err(io::Error::other(format!(
                "TAP sidecar did not accept {addr} within {}s",
                READY_TIMEOUT.as_secs()
            )));
        }
        thread::sleep(READY_INTERVAL);
    }
}

fn container_running() -> io::Result<bool> {
    let output = process::output_timeout(
        "docker",
        &["inspect", "-f", "{{.State.Running}}", CONTAINER],
        COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        let detail = process::output_detail(&output);
        if detail.to_ascii_lowercase().contains("no such object") {
            return Ok(false);
        }
        return process::check_output(
            "docker",
            &["inspect", "-f", "{{.State.Running}}", CONTAINER],
            output,
            AllowedFailure::None,
        )
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

fn docker_rm_quiet() {
    let _ = process::output_timeout("docker", &["rm", "-f", CONTAINER], COMMAND_TIMEOUT);
}

fn dump_sidecar_logs() {
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

/// Bring up a TAP on this machine, with no container in the picture.
///
/// The actual `ip` calls live in `interface::tap::ensure_iface`, which is the
/// single implementation shared with the sidecar and the terminal UI.
fn local_linux_up(cfg: &Config) -> io::Result<()> {
    crate::interface::tap::ensure_iface(&cfg.iface, cfg.linux_addr)?;
    crate::log::status::ok(format!(
        "local TAP {} up ({}/24)",
        cfg.iface, cfg.linux_addr
    ));
    Ok(())
}
