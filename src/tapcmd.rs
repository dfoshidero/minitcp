// Host helpers: start/stop the TAP sidecar (Docker) or local Linux TAP.

use std::io::{self, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::cli::Config;
use crate::interface::fwd::DEFAULT_FWD;

pub(crate) const CONTAINER: &str = "minitcp-tap";
const IMAGE: &str = "ghcr.io/dfoshidero/minitcp:latest";

const READY_TIMEOUT: Duration = Duration::from_secs(90);
const READY_INTERVAL: Duration = Duration::from_millis(200);

pub fn tap_up(cfg: &Config) -> io::Result<()> {
    if docker_ok() {
        return docker_up(cfg);
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
    if docker_ok() {
        let status = Command::new("docker")
            .args(["rm", "-f", CONTAINER])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            eprintln!("stopped {CONTAINER}");
            return Ok(());
        }
    }
    if cfg!(target_os = "linux") {
        let _ = Command::new("sudo")
            .args(["ip", "link", "delete", &cfg.iface])
            .status();
        eprintln!("removed {} if it existed", cfg.iface);
        return Ok(());
    }
    Ok(())
}

fn docker_ok() -> bool {
    Command::new("docker")
        .args(["info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn docker_up(cfg: &Config) -> io::Result<()> {
    if !container_running() {
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
        let status = Command::new("docker").args(&args).status()?;
        if !status.success() {
            dump_sidecar_logs();
            return Err(io::Error::other("TAP sidecar failed to start"));
        }
    }

    wait_for_sidecar(cfg)?;
    eprintln!(
        "TAP sidecar up; Linux  {} on {}  (host stack: {})",
        cfg.linux_addr,
        cfg.iface,
        cfg.fwd_addr()
    );
    Ok(())
}

fn wait_for_sidecar(cfg: &Config) -> io::Result<()> {
    let addr = cfg.fwd_addr();
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if TcpStream::connect(&addr).is_ok() {
            return Ok(());
        }
        if !container_running() {
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

fn container_running() -> bool {
    Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", CONTAINER])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "true")
        .unwrap_or(false)
}

fn docker_rm_quiet() {
    let _ = Command::new("docker")
        .args(["rm", "-f", CONTAINER])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn dump_sidecar_logs() {
    match Command::new("docker").args(["logs", CONTAINER]).output() {
        Ok(out) => {
            let _ = io::stderr().write_all(&out.stdout);
            let _ = io::stderr().write_all(&out.stderr);
        }
        Err(e) => eprintln!("could not read docker logs: {e}"),
    }
}

fn local_linux_up(cfg: &Config) -> io::Result<()> {
    let user = std::env::var("USER").unwrap_or_else(|_| "netstack".into());
    run_ok(&[
        "sudo", "ip", "tuntap", "add", "dev", &cfg.iface, "mode", "tap", "user", &user,
    ])?;
    let cidr = format!("{}/24", cfg.linux_addr);
    let _ = Command::new("sudo")
        .args(["ip", "addr", "add", &cidr, "dev", &cfg.iface])
        .status();
    run_ok(&["sudo", "ip", "link", "set", "dev", &cfg.iface, "up"])?;
    eprintln!("local TAP {} up ({})", cfg.iface, cidr);
    Ok(())
}

fn run_ok(args: &[&str]) -> io::Result<()> {
    let mut cmd = Command::new(args[0]);
    cmd.args(&args[1..]);
    let status = cmd.status()?;
    // tuntap add fails if it already exists; ignore that.
    if !status.success() {
        let _ = io::stderr().write_all(b"");
    }
    Ok(())
}
