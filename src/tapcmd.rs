// Host helpers: start/stop the TAP sidecar (Docker) or local Linux TAP.

use std::io::{self, Write};
use std::process::Command;

use crate::cli::Config;
use crate::interface::fwd::DEFAULT_FWD;

pub(crate) const CONTAINER: &str = "minitcp-tap";
const IMAGE: &str = "ghcr.io/dfoshidero/minitcp:latest";

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

pub fn tap_down() -> io::Result<()> {
    if docker_ok() {
        let status = Command::new("docker")
            .args(["rm", "-f", CONTAINER])
            .status()?;
        if status.success() {
            eprintln!("stopped {CONTAINER}");
            return Ok(());
        }
    }
    if cfg!(target_os = "linux") {
        let _ = Command::new("sudo")
            .args(["ip", "link", "delete", "tap0"])
            .status();
        eprintln!("removed tap0 if it existed");
        return Ok(());
    }
    Ok(())
}

fn docker_ok() -> bool {
    Command::new("docker")
        .args(["info"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn docker_up(cfg: &Config) -> io::Result<()> {
    let running = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", CONTAINER])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "true")
        .unwrap_or(false);
    if running {
        eprintln!("{CONTAINER} already running");
        return Ok(());
    }
    let _ = Command::new("docker")
        .args(["rm", "-f", CONTAINER])
        .status();

    let port = DEFAULT_FWD.split(':').next_back().unwrap_or("7946");
    let mut args = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        CONTAINER.into(),
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
    if cfg.no_create_tap {
        args.push("--no-create-tap".into());
    }
    let status = Command::new("docker").args(&args).status()?;
    if !status.success() {
        return Err(io::Error::other("TAP sidecar failed to start"));
    }
    eprintln!(
        "TAP sidecar up; Linux  {} on {}  (host stack: {DEFAULT_FWD})",
        cfg.linux_addr, cfg.iface
    );
    Ok(())
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
