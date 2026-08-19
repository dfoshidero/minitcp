# minitcp

A small userspace TCP/IP stack in Rust. Linux keeps its stack on one side of a virtual cable; MiniTCP is the machine on the other side.

Linux owns `10.0.0.1` on TAP interface `tap0`. MiniTCP pretends to be another machine at `10.0.0.2` with MAC `02:00:00:00:00:02`.

Licensed under [MIT](LICENSE). Pull requests: [CONTRIBUTING.md](docs/CONTRIBUTING.md).

Terms used in the code are defined in [GLOSSARY.md](docs/GLOSSARY.md).

## Install

```bash
curl -fsSL https://github.com/dfoshidero/minitcp/releases/latest/download/install.sh | sh
minitcp tap up    # optional; needs Docker
minitcp           # TUI on this terminal; : is host $SHELL
minitcp tap down
```

That puts `minitcp` in `~/.local/bin` (add that directory to `PATH` if the script says so). Pin a release with `VERSION=1.1.0` in front of the curl.

TAP is a Linux kernel device. `minitcp tap up` starts a sidecar that owns `tap0` and forwards frames to `127.0.0.1:7946`. On Linux with `/dev/net/tun`, MiniTCP can use a local TAP instead (no Docker). The host does not get a route into `10.0.0.2`; ping that address from Linux that owns the TAP (the sidecar, or this machine if TAP is local). The `p` key in the TUI does that for you when the sidecar is up.

Hacking on this repo: Dev Container or `cargo run` (below).

## Where this sits (OSI)

The OSI model splits networking into seven layers. Think of a letter: the paper is the message, the address form is IPv4, the envelope is Ethernet, and TAP is the fake cable that carries the envelope. MiniTCP does not replace the physical NIC. It starts at the Ethernet header and builds toward TCP.

| Layer | Name | What it does | MiniTCP |
| --- | --- | --- | --- |
| 7 | Application | HTTP, DNS, ping's user-facing side | later |
| 6–5 | Presentation / Session | encoding, connections as apps see them | skip; TCP/IP folds these into 7 and 4 |
| 4 | Transport | TCP / UDP ports and reliability | later |
| 3 | Network | IPv4 addresses and routing | **here** — parse IPv4, answer ICMP echo (ping) |
| 2 | Data link | Ethernet MACs, ARP ("who has this IP?") | Ethernet + ARP reply |
| 1 | Physical | bits on a wire | Linux TAP — a virtual Ethernet cable |

TAP is Layer 2: the program reads and writes whole Ethernet frames. TUN would be Layer 3 (raw IP). MiniTCP uses TAP so Ethernet and ARP stay in userspace.

When you `ping 10.0.0.2`, Linux first needs a MAC for that IP, so it broadcasts ARP on `tap0`. MiniTCP answers: `10.0.0.2` is at `02:00:00:00:00:02`. Linux then sends an ICMP Echo Request (type 8). MiniTCP replies with Echo Reply (type 0), wrapped in IPv4 and Ethernet.

```
ping 10.0.0.2
        │
        ▼
   Linux (10.0.0.1)  ── Ethernet frames ──►  MiniTCP (10.0.0.2)
        tap0
```

## Open the Dev Container

You need Docker running (Docker Engine on Linux, or Docker Desktop with WSL2). Open this folder in Cursor or VS Code with the Dev Containers extension.

If you use WSL, confirm Docker is reachable, then open the repo from WSL:

```bash
docker info
docker ps
code .
```

When prompted, choose **Reopen in Container**. If no prompt appears, run **Dev Containers: Reopen in Container** from the Command Palette.

Confirm you are `netstack` and the environment is ready:

```bash
whoami
id
rustc --version
cargo --version
sudo -n whoami
ls -l /dev/net/tun
```

Edit files as `netstack`, not with `sudo`. If the workspace is not owned by you:

```bash
sudo chown -R netstack:netstack /workspaces/minitcp
```

## Bring up tap0

`tap0` is a live kernel device and disappears when the container restarts. The `minitcp` lab creates and configures it automatically. For the manual workflow, run:

```bash
# A TAP is a fake Ethernet cable. Linux holds one end - MiniTCP holds the other.
# Inspect the script below to see its setup.
./scripts/setup-tap.sh
```

That creates the fake Ethernet cable, gives Linux `10.0.0.1/24` on it, and plugs it in (`UP`). It is safe to run more than once.

`tap0` should be UP, and the routing table should include `10.0.0.0/24 dev tap0`. If this fails, check `sudo -n whoami`, `/dev/net/tun`, and that you are inside the Dev Container. Do not debug Rust until this works.

## Run MiniTCP

Open the full lab:

```bash
minitcp
# or, while developing (always builds current source):
cargo run
```

The Dev Container installs `minitcp` once when the container is created. After you change the code, either use `cargo run` or reinstall the command:

```bash
cargo install --path .
```

`minitcp` on your PATH is that installed binary. Restarting the lab with `r` does not rebuild it.

The screen contains three independent terminal-style panes. The blue **MiniTCP Core** pane is the stack itself; the dark external panes are commands that observe or interact with it:

- **MiniTCP Core** — MiniTCP's protocol log (`IN` / `OUT` / `DROP`). Press `v` for one line per exchange.
- **TAP Capture** — `tcpdump` watching live traffic on the virtual cable.
- **External Tools** — output from ping, neighbour-table commands, and commands you type.

| Key | Action |
| --- | --- |
| `Tab` | Focus the next pane |
| `1` / `2` / `3` | Focus stack / packets / actions directly |
| `↑` / `↓` | Scroll the focused pane one line |
| `PageUp` / `PageDown` | Scroll the focused pane one page |
| `a` or `End` | Toggle/resume live output for the focused pane |
| `:` | Type a shell command; `Enter` runs it and `Esc` cancels |
| `p` | Ping `10.0.0.2` while stack and tcpdump keep running |
| `n` | Show `ip neigh` |
| `f` | Flush the neighbour table |
| `d` | Cycle tcpdump through all / ARP / IP |
| `v` | Toggle quiet one-liners (restarts the stack) |
| `c` | Clear the focused pane |
| `r` | Restart the stack |
| `t` | Restart tcpdump |
| `q` | Stop child processes and quit |

Typed commands run non-interactively in the actions pane. This is useful for commands such as `ip addr show tap0`, `ip route`, or `uname -a`; full-screen interactive programs should still be opened in a separate terminal.

Scrolling up pauses that focused pane, which is marked `PAUSED`. Reaching the bottom, pressing `End`, or enabling live output with `a` resumes trailing output. If new data arrives while a pane is unfocused, that pane automatically returns to its newest line.

Press `p` to ping `10.0.0.2`. You should see replies from MiniTCP (`64 bytes from 10.0.0.2`).

## Flags and config

Everything is optional. Defaults are the lab above (`tap0`, MiniTCP `10.0.0.2` / `02:00:00:00:00:02`, Linux `10.0.0.1`). `minitcp --help` lists commands and flags.

IP and MAC are MiniTCP's identity (`minitcp identity addr` / `mac`). The cable is `minitcp tap iface` / `addr` / `tun`. One-shot `--addr` and `--iface` still override a single run.

```bash
minitcp --quiet
minitcp tap iface tap1
minitcp stack --write out.pcap
minitcp replay out.pcap -q
minitcp pcap out.pcap
minitcp stack --drop icmp -c 5
```

Same knobs can live in `minitcp.toml` in the working directory, or `--config FILE`. Command line wins over the file.

```toml
iface = "tap1"
addr = "10.0.0.3"
quiet = true
drop = ["icmp"]
```

Same file works next to the host binary; the sidecar does not need it.

## Pcap (record and replay)

A **pcap** is a file of Ethernet frames, the same format tcpdump and Wireshark use. MiniTCP can record live TAP traffic and later replay it without `/dev/net/tun` (useful in CI).

```bash
minitcp stack --write out.pcap -q    # record while pinging in another terminal
minitcp pcap out.pcap                # list each frame's EtherType
minitcp replay out.pcap -q           # feed those frames to the stack again
```

`--write` also works with `replay`. Terms: [GLOSSARY.md](docs/GLOSSARY.md) (pcap). Implementation: `src/interface/pcap.rs`.

### Manual three-terminal workflow

Use this if you want to inspect each command without the lab.

Terminal 1:

```bash
./scripts/setup-tap.sh
minitcp stack
```

Terminal 2:

```bash
# Forget any old MAC address for 10.0.0.2 so Linux asks ARP again.
sudo ip neigh flush dev tap0

# One ping. MiniTCP should answer.
ping -c 1 -W 1 10.0.0.2

# Neighbour table, essentially = "phone book of IP to MAC on this cable."
ip neigh show dev tap0
```

`ping` should print `64 bytes from 10.0.0.2`. `ip neigh show dev tap0` should contain `10.0.0.2` at `02:00:00:00:00:02`.

Watch ARP, then ICMP, on the wire:

```bash
sudo tcpdump -eni tap0 arp
sudo tcpdump -eni tap0 icmp
```

You should see Linux ask "who has `10.0.0.2`, tell `10.0.0.1`" and MiniTCP reply "`10.0.0.2` is at `02:00:00:00:00:02`". Then an ICMP echo request `10.0.0.1 > 10.0.0.2` and MiniTCP's echo reply `10.0.0.2 > 10.0.0.1` with the same identifier and sequence.

Parser tests (no TAP required):

```bash
cargo test
```

## What you should see

Verbose is the default: it peels Ethernet / IPv4 / ICMP. Press `v`, or run `minitcp stack -q`, for one line per exchange. TCP and UDP are not decoded yet.

A successful `ping 10.0.0.2` looks like this:

```
23:12:05  [IN]    ethernet  L2  02:00:00:00:00:01 -> 02:00:00:00:00:02  ethertype 0x0800
          [..]    ipv4      L3  10.0.0.1 -> 10.0.0.2  ttl=64 proto=icmp payload=64
          [..]    └── icmp  L3  type=8 code=0 id=1 seq=1  len=64
          [OUT]   ethernet  L2  02:00:00:00:00:02 -> 02:00:00:00:00:01  ethertype 0x0800
          [..]    ipv4      L3  10.0.0.2 -> 10.0.0.1  ttl=64 proto=icmp payload=64
          [..]    └── icmp  L3  type=0 code=0 id=1 seq=1  len=64
```

Quiet (`v` or `minitcp stack -q`) is one line per exchange:

```
23:12:05  arp  10.0.0.1 -> 10.0.0.2  who-has
23:12:05  icmp  10.0.0.1 -> 10.0.0.2  echo id=1 seq=1  len=64
```

| Field | Meaning |
| --- | --- |
| time | `HH:MM:SS` on the first line of the event |
| `[IN]` / `[OUT]` / `[DROP]` | verbose: accepted, replied, or ignored |
| `[..]` | verbose continuation; `└──` is the IPv4 payload |
| `echo id=` | quiet ping; request and reply as one line |
| `who-has` | quiet ARP; MAC is in verbose |
| `id` / `seq` | ping identifier and sequence |
| `len=` | ICMP message size |

IPv6 is hidden in quiet mode. UDP and TCP currently log `[DROP]  …  not implemented`.

After the ARP reply, Linux should stop asking for `10.0.0.2` while the neighbour entry is valid, and the next frame should be IPv4.

IPv4 notes that are easy to miss:

- Byte 0 packs two things: version (must be 4) and IHL (header length in 4-byte words; `5` means 20 bytes).
- Total Length is header plus payload. Ethernet may pad the frame, so trust that field, not "the rest of the TAP buffer."
- The header checksum is a math stamp. A valid header checksums to `0`. MiniTCP rejects a bad stamp.
- Fragments are a torn letter. v1 refuses them on purpose (`More Fragments` or a non-zero offset).

## Layout

- `docs/GLOSSARY.md` — short definitions of terms the code uses.
- `docker/Dockerfile` — TAP sidecar image (`ghcr.io/dfoshidero/minitcp`). The Dev Container image is `.devcontainer/Dockerfile`.
- `scripts/install.sh` — one-line install of the host binary from GitHub Releases.
- `scripts/setup-tap.sh` — manually create and bring up `tap0` in the Dev Container; the lab does this automatically.
- `src/main.rs` — command dispatcher: terminal lab by default, `stack`, `tap`, `identity`, `replay`, `pcap`.
- `src/cli/` — flags, `minitcp.toml`, `--help`, and parse errors.
- `src/stack.rs` — frame loop: TAP, TCP sidecar frames, pcap, or hex; dispatch to a protocol; write a reply.
- `src/tapcmd.rs` — host `tap up` / `tap down` (Docker sidecar or local Linux TAP).
- `src/update.rs` — optional GitHub Releases nag (prompt only).
- `src/log.rs` — quiet one-liner, or verbose `[IN]` / `[OUT]` / `[..]` peel.
- `src/tui/` — terminal UI: split panes, child processes, key actions, and scrollback.
- `src/interface/tap.rs` — open `/dev/net/tun`, read/write raw frames. No protocol parsing.
- `src/interface/fwd.rs` — length-prefixed Ethernet frames over TCP (sidecar).
- `src/interface/pcap.rs` — classic pcap read/write, `pcap`, and hex frames.
- `src/proto/` — wire formats MiniTCP speaks:
  - `ethernet.rs` — Ethernet II: destination MAC, source MAC, EtherType, payload.
  - `arp.rs` — answer "who has `10.0.0.2`?" with MiniTCP's MAC.
  - `ipv4.rs` — parse/validate a 20-byte IPv4 header, reject fragments, serialize one back.
  - `icmp.rs` — turn ICMP Echo Request (type 8) into Echo Reply (type 0).
  - `checksum.rs` — Internet checksum (one's complement). IPv4 uses it now; TCP/UDP will later.
