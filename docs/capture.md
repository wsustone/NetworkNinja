# Listening to DIS traffic

NetworkNinja receives DIS the way a simulator does: from UDP sockets. It never sends. This page
covers telling it where to listen: ports, broadcast, multicast groups and network interfaces.
It also covers the operating-system settings that decide whether it sees every packet.

## Quick reference

| Exercise sends… | Listener |
| --- | --- |
| Broadcast on port 3000 (the common DIS default) | `--listen 3000`, or `[[listen]] port = 3000` |
| Multicast group 239.1.2.3, port 3000 | `--listen 3000:239.1.2.3@en0` |
| Several ports or groups | one `--listen` (or `[[listen]]`) each |
| To a simulator on this same machine | add `share = true` (`--share`), broadcast and multicast only (see below) |

```sh
nn-server interfaces                                   # which NIC is which
nn-server serve --listen 3000 --listen 3001:239.1.2.10@eth1
nn-server serve --config nn.toml                       # the same, from a file
```

Start from [`nn.example.toml`](../nn.example.toml). A config file holds the listeners and the
`[serve]` settings (dashboard address, database, SISO file, rule packs, capture, TLS).
Command-line flags override `[serve]` keys. Listeners given on the command line replace the
file's `[[listen]]` blocks. `scripts/nn` uses a config file when `NN_CONFIG` is set.

## Broadcast, multicast and unicast

- **Broadcast** (to 255.255.255.255 or a subnet's broadcast address, e.g. 10.0.0.255): every
  machine on the subnet receives it. A listener bound to `0.0.0.0` (the default) receives it
  with no other setting. Binding to one interface's own address can miss it, which is why the
  default bind is 0.0.0.0.
- **Multicast** (224.0.0.0–239.255.255.255): only machines that *join* the group receive it.
  List each group in `multicast`, and set `interface` to the NIC on the exercise network.
  Without an interface the OS picks one, which on a laptop with Wi-Fi and a lab NIC is often the
  wrong one. The join sends an IGMP report; switches with IGMP snooping only forward the group
  to ports that joined.
- **Unicast** (to one machine's address): only that machine receives it. To monitor unicast
  traffic between other machines, NetworkNinja must be the destination, or see a copy of the
  traffic: a switch SPAN or mirror port, captured with packet capture (pcap import today; live
  libpcap capture is planned).

## Sharing a port with a simulator on the same machine

Normally only one program can listen on a UDP port. If a simulator, gateway or another monitor
on this machine already has port 3000, the server stops with "address in use" and suggests
sharing.

`share = true` (`--share`) sets SO_REUSEADDR, plus SO_REUSEPORT on macOS, Linux and BSD, so
several programs can bind the port. **Only the simulator's broadcast and multicast traffic is
safe to share.** Every sharing socket gets its own copy of those. A *unicast* datagram to a
shared port is delivered to only one of the sharing programs, chosen by the OS, so sharing a
port that carries unicast can take packets away from the simulator. On macOS and Linux,
sharing also needs the other program to have allowed it when it bound the port. If it didn't,
the bind still fails; run the monitor on another machine on the same network, or capture from a
mirror port.

## Not missing packets: receive buffers

The OS queues arriving datagrams in a per-socket receive buffer. If NetworkNinja falls behind
for a moment (a burst, a disk flush), the queue absorbs it. If the queue fills, the OS drops
packets silently, and the monitor then reports timeouts that didn't happen on the wire.

Each listener asks for 8 MB (`receive_buffer_mb`, `--receive-buffer`). The startup log and
`/api/inputs` show what the OS granted, and the log warns when it's less than requested:

| OS | Limit | Raise it (as root) |
| --- | --- | --- |
| Linux | `net.core.rmem_max` (often 208 KB) | `sysctl -w net.core.rmem_max=33554432` (persist in `/etc/sysctl.d/`) |
| macOS | `kern.ipc.maxsockbuf` (often 8 MB) | `sysctl -w kern.ipc.maxsockbuf=33554432` |
| Windows | no small default cap | – |

Linux reports twice the size it reserves for data, so a granted 16 MB there means an 8 MB
queue.

## Firewalls

- **macOS:** the application firewall may ask to allow incoming connections the first time.
  Allow it, or packets are silently discarded.
- **Windows:** the first listen triggers a firewall prompt. Allow it on private networks, or
  add an inbound UDP rule for the port.
- **Linux:** with `ufw` or `firewalld`, open the UDP port, e.g. `ufw allow 3000/udp`.

## Is it working?

- **Startup log:** one line per listener, with its address, groups and interface, whether it's
  shared, and its receive buffer.
- **Dashboard:** the *inputs* line under the health strip shows each listener's datagram rate.
  It turns amber when a listener has received nothing for 10 s, and red on receive errors.
- **`GET /api/inputs`:** the same as JSON, with counters, seconds since the last datagram, and
  the last error.

When a listener stays quiet:

1. Is the exercise on that port? `tcpdump -ni en0 udp port 3000`, or Wireshark, shows whether
   packets reach the machine at all.
2. **Multicast:** are you joined on the interface the traffic arrives on? Check
   `nn-server interfaces` and the `interface` setting. Does the switch forward the group
   (IGMP snooping, multicast routing between VLANs)? Is the sender's TTL big enough to cross
   any routers?
3. **Broadcast:** broadcast doesn't cross routers. The monitor must be on the same subnet or
   VLAN as the simulators.
4. **Firewall:** see above.

## Generator

To test a setup without an exercise, the generator can send the same ways:

```sh
nn-generator --target 10.0.0.255:3000 --broadcast            # subnet broadcast
nn-generator --target 239.1.2.3:3000 --iface en0 --ttl 1     # multicast out of en0
```
