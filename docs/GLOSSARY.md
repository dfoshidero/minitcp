# Glossary

Short meanings for words MiniTCP uses. Comments in the code show *where* we apply them; this page is the dictionary.

## Layers and pieces

**OSI model** — A 7-layer cartoon of networking. MiniTCP starts at layer 2 (Ethernet) and is working up toward layer 4 (TCP).

**Frame** — One Ethernet envelope on the cable: destination MAC, source MAC, EtherType, then payload.

**Packet** — The IPv4 letter *inside* that envelope: source IP, dest IP, protocol, then payload.

**Header** — The form glued on the front (Ethernet 14 bytes, IPv4 usually 20). **Payload** is whatever comes after it.

**Encapsulation** — Nesting: ICMP sits in IPv4, IPv4 sits in Ethernet. Like a letter in an addressed form in an envelope.

## Addresses

**MAC address** — 6-byte nametag on *this cable* (`02:00:00:00:00:02`). Ethernet uses it.

**IPv4 address** — 4-byte house number on the internet (`10.0.0.2`). IPv4 uses it.

**Broadcast** — Send to everyone on the cable. Ethernet broadcast MAC is `ff:ff:ff:ff:ff:ff`. ARP "who has?" uses it.

**`10.0.0.1/24`** — Linux's address plus a mask. `/24` means "the first 24 bits are the street; the last 8 are the house." That street is `10.0.0.0`–`10.0.0.255`.

**Neighbour / ARP cache** — Linux's phone book of "this IP is at this MAC" on `tap0`. `ip neigh show dev tap0` prints it.

## Protocols MiniTCP touches

**Ethernet II** — Layer-2 envelope. Bytes 0–5 dest MAC, 6–11 source MAC, 12–13 EtherType, 14+ payload.

**EtherType** — Two-byte label on the envelope. `0x0800` = IPv4, `0x0806` = ARP, `0x86dd` = IPv6 (we ignore it).

**ARP** — "Who lives at this IP?" Linux must learn our MAC before it can send IPv4 to `10.0.0.2`.

**IPv4** — Layer-3 letter with source/dest IPs. MiniTCP parses it and names the protocol inside. It does not route or fragment.

**ICMP** — Protocol number 1, carried inside IPv4. Ping is Echo Request (type 8); MiniTCP answers with Echo Reply (type 0).

**TCP** — Protocol number 6. Reliable streams. Later.

**UDP** — Protocol number 17. Datagrams. Later.

**TTL** — "Lives left." Each hop subtracts 1. At 0 the packet dies so it cannot loop forever.

## IPv4 header details

**Version / IHL** — Packed in byte 0. High 4 bits = version (must be 4). Low 4 bits = IHL.

**IHL** — Header length in 4-byte words. `5` → 20 bytes, the usual header with no options.

**Total Length** — Header plus payload, in bytes. Ethernet may pad the frame, so trust this field, not `input.len()`.

**Fragment** — A packet torn into pieces. Bytes 6–7: flags + 13-bit offset. MiniTCP v1 rejects a non-zero offset or the More Fragments bit.

**Internet checksum** — Add the header as 16-bit big-endian words, fold the overflow, flip all bits. A *valid* header, checksum field included, checksums to `0`.

**One's complement** — The "flip all bits" step (`!` in Rust). Not the same as two's complement (how CPUs usually negate integers).

## TAP and Linux

**TAP** — A fake Ethernet cable. Linux holds one end (`tap0`); MiniTCP holds the other by reading `/dev/net/tun`. Layer 2: whole frames.

**TUN** — Same idea, but layer 3: raw IP, no Ethernet. MiniTCP does not use TUN.

**`/dev/net/tun`** — Kernel file that *is* the virtual cable once you ioctl it.

**ioctl** — A special system call: "configure this file." `TUNSETIFF` means "this fd is TAP named tap0."

**`IFF_TAP | IFF_NO_PI`** — Two flag bits OR'd into one number. TAP = Ethernet frames. NO_PI = don't glue an extra kernel prefix on the front.

**Userspace** — Our Rust process, not the kernel. Linux already has a TCP/IP stack; MiniTCP is a second stack talking over TAP.

## Byte order and bit tricks

**Big-endian / network order** — Multi-byte numbers on the wire put the high byte first. `u16::from_be_bytes([0x08, 0x00])` is `0x0800`. Your CPU might store the opposite internally; we convert at the edge.

**Nibble** — 4 bits, half a byte. Byte `0x45` is nibble `4` and nibble `5`.

**`>>` / `<<`** — Slide bits. Right-shift drops the low bits (parse: pull version out of a shared byte). Left-shift makes room in the low bits (checksum leftover byte; pack version back when writing).

**`&` (AND)** — Keep only some bits. Used to pull header length out of byte 0, or fragment flags out of a packed 16-bit field.

**`|` (OR)** — Combine bits. TAP flags share one kernel field; version and IHL share byte 0 when we write.

**`!` (NOT)** — Flip every bit. Last step of the Internet checksum.
