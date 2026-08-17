# minitcp

A small userspace TCP/IP stack in Rust. Linux keeps its stack on one side of a virtual cable; MiniTCP is the machine on the other side.

Linux owns `10.0.0.1` on TAP interface `tap0`. MiniTCP pretends to be another machine at `10.0.0.2` with MAC `02:00:00:00:00:02`.

Work inside the Dev Container. It has Rust, `/dev/net/tun`, and the privileges needed to create network interfaces.

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

`tap0` is not created in the image. It is a live kernel device and disappears when the container restarts. Create it by hand so you can see the route and the ARP.

```bash
# A TAP is a fake Ethernet cable. Linux holds one end; MiniTCP holds the other.
# `user netstack` lets cargo run attach without being root.
sudo ip tuntap add dev tap0 mode tap user netstack

# Set Linux's address on this fake cable. /24 means "this house and its 256-address street."
sudo ip addr add 10.0.0.1/24 dev tap0

# Essentially plugging the ethernet cable in. Until it is UP, nothing can be sent.
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

## What you should see

`cargo run` prints each Ethernet frame, then IPv4 details when the EtherType is IPv4:

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

- `src/interface/tap.rs` — open `/dev/net/tun`, read/write raw frames. No protocol parsing.
- `src/ethernet.rs` — Ethernet II: destination MAC, source MAC, EtherType, payload.
- `src/arp.rs` — answer "who has `10.0.0.2`?" with MiniTCP's MAC.
- `src/checksum.rs` — Internet checksum (one's complement). IPv4 uses it now; TCP/UDP will later.
- `src/ipv4.rs` — parse/validate a 20-byte IPv4 header, reject fragments, serialize one back.
- `src/main.rs` — attach to `tap0`, reply to ARP, print IPv4 protocol.
