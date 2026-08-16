# minitcp

A userspace Ethernet/TCP stack. Linux owns `10.0.0.1` on TAP interface `tap0`; MiniTCP pretends to be another machine at `10.0.0.2`.

Work inside the Dev Container. It has Rust, `/dev/net/tun`, and the privileges needed to create network interfaces.

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

TAP presents Ethernet frames (Layer 2). TUN presents IP packets (Layer 3). This project uses TAP because it implements Ethernet and ARP itself.

```bash
sudo ip tuntap add dev tap0 mode tap user netstack
sudo ip addr add 10.0.0.1/24 dev tap0
sudo ip link set dev tap0 up
ip addr show tap0
ip route
```

`tap0` should be UP, and the routing table should include `10.0.0.0/24 dev tap0`. If this fails, check `sudo -n whoami`, `/dev/net/tun`, and that you are inside the Dev Container. Do not debug Rust until this works.

`tap0` persists until the container restarts. Recreate it if `ip link show tap0` says the device does not exist.

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

## What you should see

`cargo run` prints each Ethernet frame as a length plus a short hex dump. The ARP request from ping looks like:

```
received 42 bytes
ff ff ff ff ff ff 9a ba d6 d1 53 a1 08 06 ... 0a 00 00 01
```

| Bytes | Meaning |
| --- | --- |
| `ff ff ff ff ff ff` | Ethernet broadcast destination |
| next 6 bytes | Linux's MAC on `tap0` |
| `08 06` | EtherType ARP |
| `0a 00 00 01` | sender IP `10.0.0.1` |

You will also see IPv6 multicast frames starting with `33 33` and EtherType `86 dd`. Ignore those for now.

`tcpdump` should report the same request: who has `10.0.0.2`, tell `10.0.0.1`.

## Code notes

`src/interface/tap.rs` is Linux I/O only. It does not parse Ethernet, ARP, or IP.

It opens `/dev/net/tun` and attaches to `tap0` with `ioctl(TUNSETIFF)` using `IFF_TAP | IFF_NO_PI`:

- `IFF_TAP` — Ethernet frames, not IP packets
- `IFF_NO_PI` — no extra packet-info prefix, so the buffer starts at the Ethernet header

The read loop uses a 2048-byte buffer, large enough for a 1500-byte MTU plus headers. `write_frame` is ready but unused until MiniTCP starts answering ARP.
