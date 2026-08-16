# minitcp

A small userspace TCP/IP stack in Rust. Use it as a practice lab: Linux keeps a real network stack on one side of a virtual cable; you implement the other side, layer by layer.

Linux owns `10.0.0.1` on TAP interface `tap0`. MiniTCP pretends to be another machine at `10.0.0.2`.

Work inside the Dev Container. It has Rust, `/dev/net/tun`, and the privileges needed to create network interfaces.

## Where this sits (OSI)

The OSI model splits networking into seven layers. MiniTCP does not replace the physical NIC. It starts at the Ethernet header and will climb toward TCP.

| Layer | Name | What it does | MiniTCP |
| --- | --- | --- | --- |
| 7 | Application | HTTP, DNS, ping's user-facing side | later |
| 6–5 | Presentation / Session | encoding, connections as apps see them | skip; TCP/IP folds these into 7 and 4 |
| 4 | Transport | TCP / UDP ports and reliability | later |
| 3 | Network | IPv4 addresses and routing | later |
| 2 | Data link | Ethernet MACs, ARP ("who has this IP?") | **here** — Ethernet parse/serialize works |
| 1 | Physical | bits on a wire | Linux TAP — a virtual Ethernet cable |

TAP is Layer 2: your program reads and writes whole Ethernet frames. TUN would be Layer 3 (raw IP). This project uses TAP because Ethernet and ARP are part of the exercise.

When you `ping 10.0.0.2`, Linux does this from the top down: ICMP (over IP) needs a next-hop MAC, so it broadcasts ARP on `tap0`. MiniTCP currently parses that Ethernet frame. It does not answer ARP yet, so ping failing is expected.

```
ping 10.0.0.2
        │
        ▼
   Linux (10.0.0.1)  ── Ethernet frames ──►  MiniTCP (10.0.0.2)
        tap0                                      your code
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

`tap0` is not created in the image. It is a live kernel device and disappears when the container restarts. Create it by hand so you can see the route and the ARP.

```bash
sudo ip tuntap add dev tap0 mode tap user netstack
sudo ip addr add 10.0.0.1/24 dev tap0
sudo ip link set dev tap0 up
ip addr show tap0
ip route
```

`tap0` should be UP, and the routing table should include `10.0.0.0/24 dev tap0`. If this fails, check `sudo -n whoami`, `/dev/net/tun`, and that you are inside the Dev Container. Do not debug Rust until this works.

## Run MiniTCP

Terminal 1:

```bash
cargo run
```

Terminal 2:

```bash
ping -c 1 -W 1 10.0.0.2
```

Ping will fail. That is expected: Linux ARPs for `10.0.0.2`, and nothing answers yet.

Optional: watch the same ARP on the wire.

```bash
sudo tcpdump -eni tap0 arp
```

If a previous ping left a failed neighbour entry, flush it and ping again:

```bash
sudo ip neigh flush dev tap0
ping -c 1 -W 1 10.0.0.2
```

Parser tests (no TAP required):

```bash
cargo test
```

## What you should see

`cargo run` prints each frame as source MAC, destination MAC, and EtherType:

```
02:00:00:00:00:01 -> ff:ff:ff:ff:ff:ff Arp
02:00:00:00:00:01 -> 33:33:00:00:00:01 Unknown(34525)
```

| Field | Meaning |
| --- | --- |
| left MAC | Linux's MAC on `tap0` |
| `ff:ff:ff:ff:ff:ff` | Ethernet broadcast (ARP who-has) |
| `Arp` | EtherType `0x0806` |
| `Unknown(34525)` | IPv6 (`0x86dd`). Ignore for now |

`tcpdump` should report the same request: who has `10.0.0.2`, tell `10.0.0.1`.

## Layout

- `src/interface/tap.rs` — open `/dev/net/tun`, read/write raw frames. No protocol parsing.
- `src/ethernet.rs` — Ethernet II: destination MAC, source MAC, EtherType, payload.
- `src/main.rs` — attach to `tap0` and print parsed frames.
