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
| 3 | Network | IPv4 addresses and routing | **here** — parse IPv4, name ICMP/UDP/TCP |
| 2 | Data link | Ethernet MACs, ARP ("who has this IP?") | Ethernet + ARP reply |
| 1 | Physical | bits on a wire | Linux TAP — a virtual Ethernet cable |

TAP is Layer 2: the program reads and writes whole Ethernet frames. TUN would be Layer 3 (raw IP). MiniTCP uses TAP so Ethernet and ARP stay in userspace.

When you `ping 10.0.0.2`, Linux first needs a MAC for that IP, so it broadcasts ARP on `tap0`. MiniTCP answers: `10.0.0.2` is at `02:00:00:00:00:02`. Linux then sends an IPv4 packet (usually ICMP echo). MiniTCP parses that header and prints the protocol. Ping still fails: MiniTCP does not answer ICMP yet.

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
# or, while developing:
cargo run
```

The screen contains three independent terminal-style panes. The blue **MiniTCP Core** pane is the stack itself; the dark external panes are commands that observe or interact with it:

- **MiniTCP Core** — MiniTCP's incoming Ethernet/ARP/IPv4 logs.
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
| `c` | Clear the focused pane |
| `r` | Restart the stack |
| `t` | Restart tcpdump |
| `q` | Stop child processes and quit |

Typed commands run non-interactively in the actions pane. This is useful for commands such as `ip addr show tap0`, `ip route`, or `uname -a`; full-screen interactive programs should still be opened in a separate terminal.

Scrolling up pauses that focused pane, which is marked `PAUSED`. Reaching the bottom, pressing `End`, or enabling live output with `a` resumes trailing output. If new data arrives while a pane is unfocused, that pane automatically returns to its newest line.

Ping still reports packet loss. That is expected: MiniTCP can see the IPv4/ICMP packet but does not send an echo reply yet.

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

# One ping, give up after 1 second. It will fail: we read ICMP but do not reply yet.
ping -c 1 -W 1 10.0.0.2

# Neighbour table, essentially = "phone book of IP to MAC on this cable."
ip neigh show dev tap0
```

Ping will still fail. That is expected: Linux now knows the MAC, and MiniTCP can see the IPv4/ICMP packet, but it does not send an echo reply.

`ip neigh show dev tap0` should contain `10.0.0.2` at `02:00:00:00:00:02`.

Optional: watch ARP, then IPv4, on the wire.

```bash
sudo tcpdump -eni tap0 arp
sudo tcpdump -eni tap0 ip
```

You should see Linux ask "who has `10.0.0.2`, tell `10.0.0.1`" and MiniTCP reply "`10.0.0.2` is at `02:00:00:00:00:02`". After that, tcpdump should show an IPv4 packet from `10.0.0.1` to `10.0.0.2` (ICMP echo). MiniTCP does not generate IPv4 on the wire yet, so there is no echo reply to inspect.

Parser tests (no TAP required):

```bash
cargo test
```

## Install outside the Dev Container

MiniTCP requires Linux because TAP is a Linux kernel device. On macOS or Windows, use a Linux Docker container rather than installing a native binary.

On Linux with Rust installed:

```bash
cargo install --git <repository-url>
minitcp
```

The host also needs `/dev/net/tun`, `ip`, `ping`, `tcpdump`, and permission to create network interfaces.

For a packaged container image, run it with the network capabilities and TAP device exposed:

```bash
docker run --rm -it \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --device=/dev/net/tun \
  <minitcp-image>
```

A published image and prebuilt GitHub Release binaries can be added later. The current supported download/install paths are the Dev Container and `cargo install` on Linux.

## What you should see

The `minitcp stack` pane (or the standalone command) prints each Ethernet frame, then IPv4 details when the EtherType is IPv4:

```
02:00:00:00:00:01 -> ff:ff:ff:ff:ff:ff Arp
02:00:00:00:00:01 -> 02:00:00:00:00:02 Ipv4
ipv4 10.0.0.1 -> 10.0.0.2 ttl=64 Icmp
ICMP (to be implemented)
```

| Field | Meaning |
| --- | --- |
| left MAC | Linux's MAC on `tap0` |
| `ff:ff:ff:ff:ff:ff` | shout to everyone on the cable (ARP who-has) |
| `Arp` | EtherType `0x0806` — "this envelope is an ARP note" |
| `Ipv4` | EtherType `0x0800` — "this envelope has an IPv4 letter" |
| `ttl=64` | lives left; each hop subtracts 1 |
| `Icmp` | protocol 1, the ping message inside IPv4 |

You may also see IPv6 frames with `Unknown(34525)`. Ignore those for now.

After the ARP reply, Linux should stop asking for `10.0.0.2` while the neighbour entry is valid, and the next frame should be IPv4.

IPv4 notes that are easy to miss:

- Byte 0 packs two things: version (must be 4) and IHL (header length in 4-byte words; `5` means 20 bytes).
- Total Length is header plus payload. Ethernet may pad the frame, so trust that field, not "the rest of the TAP buffer."
- The header checksum is a math stamp. A valid header checksums to `0`. MiniTCP rejects a bad stamp.
- Fragments are a torn letter. v1 refuses them on purpose (`More Fragments` or a non-zero offset).

## Layout

- `GLOSSARY.md` — short definitions of terms the code uses.
- `setup-tap.sh` — manually create and bring up `tap0`; the lab does this automatically.
- `src/frontend/mod.rs` — isolated terminal frontend: split panes, child processes, key actions, and scrollback.
- `src/stack.rs` — the raw TAP protocol loop used by `minitcp stack`.
- `src/interface/tap.rs` — open `/dev/net/tun`, read/write raw frames. No protocol parsing.
- `src/ethernet.rs` — Ethernet II: destination MAC, source MAC, EtherType, payload.
- `src/arp.rs` — answer "who has `10.0.0.2`?" with MiniTCP's MAC.
- `src/checksum.rs` — Internet checksum (one's complement). IPv4 uses it now; TCP/UDP will later.
- `src/ipv4.rs` — parse/validate a 20-byte IPv4 header, reject fragments, serialize one back.
- `src/main.rs` — command dispatcher: terminal lab by default, raw stack with `stack`.
