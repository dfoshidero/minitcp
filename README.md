# minitcp

A small userspace TCP/IP stack in Rust. Linux keeps its stack on one side of a virtual cable; MiniTCP is the machine on the other side.

Linux owns `10.0.0.1` on TAP interface `tap0`. MiniTCP pretends to be another machine at `10.0.0.2` with MAC `02:00:00:00:00:02`.

Work inside the Dev Container. It has Rust, `/dev/net/tun`, and the privileges needed to create network interfaces.

Terms used in the code are defined in [GLOSSARY.md](GLOSSARY.md).

The Dev Container installs the `minitcp` command automatically. Run it to open the terminal lab:

```bash
minitcp
```

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

## Open the environment

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
./setup-tap.sh
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

### Manual three-terminal workflow

Use this if you want to inspect each command without the lab.

Terminal 1:

```bash
./setup-tap.sh
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

## Install outside the Dev Container

MiniTCP requires Linux because TAP is a Linux kernel device. On macOS or Windows, use a Linux Docker container rather than installing a native binary.

```bash
sudo snap install minitcp
sudo snap connect minitcp:network-control
sudo snap connect minitcp:network-observe
```

`snap install minitcp` works if your user can talk to snapd without sudo. The first two `connect` commands let the snap create `tap0` and run tcpdump without `sudo`. They are needed until the Store auto-connects those plugs.

The host also needs `/dev/net/tun`, `ip`, `ping`, `tcpdump`, and permission to create network interfaces.

To build from source instead:

```bash
cargo install --git <repository-url>
minitcp
```

Releases are cut from conventional commits on `main`. `fix:` is a patch, `feat:` is a minor, and `feat!:` / `BREAKING CHANGE:` is a major. `docs:` and `ci:` do not bump the version. A bot opens a release PR that updates `Cargo.toml`. Merge that PR and CI tags `vX.Y.Z`, attaches the snap to the GitHub Release, and publishes to the Snap Store.

For a packaged container image, run it with the network capabilities and TAP device exposed:

```bash
docker run --rm -it \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --device=/dev/net/tun \
  <minitcp-image>
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

- `GLOSSARY.md` — short definitions of terms the code uses.
- `setup-tap.sh` — manually create and bring up `tap0`; the lab does this automatically.
- `src/main.rs` — command dispatcher: terminal lab by default, raw stack with `stack`.
- `src/stack.rs` — TAP loop: read a frame, dispatch to a protocol, write a reply.
- `src/log.rs` — quiet one-liner, or verbose `[IN]` / `[OUT]` / `[..]` peel.
- `src/tui/` — terminal UI: split panes, child processes, key actions, and scrollback.
- `src/interface/tap.rs` — open `/dev/net/tun`, read/write raw frames. No protocol parsing.
- `src/proto/` — wire formats MiniTCP speaks:
  - `ethernet.rs` — Ethernet II: destination MAC, source MAC, EtherType, payload.
  - `arp.rs` — answer "who has `10.0.0.2`?" with MiniTCP's MAC.
  - `ipv4.rs` — parse/validate a 20-byte IPv4 header, reject fragments, serialize one back.
  - `icmp.rs` — turn ICMP Echo Request (type 8) into Echo Reply (type 0).
  - `checksum.rs` — Internet checksum (one's complement). IPv4 uses it now; TCP/UDP will later.
