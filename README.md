# ngx-tcp-fingerprint

An nginx module that exposes a passive fingerprint of the client's TCP/IP
stack, read from the SYN that opened the connection, in the tradition of
[p0f](https://lcamtuf.coredump.cx/p0f3/): TTL, window, MSS, window scale,
option layout and header quirks. It also times the TLS 1.3 handshake's round
trip next to the kernel's TCP RTT.

A browser's User-Agent says which operating system it runs on, but the SYN
comes from the network stack that actually sent it. Residential proxies and
scraping farms that announce Windows while running on Linux boxes show up as a
Windows User-Agent with a Linux SYN: initial TTL 64 instead of 128,
`mss,sok,ts,nop,ws` options instead of `mss,nop,ws,nop,nop,sok`. The MSS tells
the link the client sits behind (Ethernet, PPPoE, a tunnel), the quirks tell a
SYN built by hand.

The TCP round trip ends at whoever acknowledges the segments, the TLS one at
whoever holds the session keys: the same machine for a direct client, but
through a tunnel (CONNECT or SOCKS proxy, residential proxy networks) TCP stops
at the exit node and TLS goes on to the real client, often far away. A direct
client shows two close values, a tunnelled one a TLS RTT well above the TCP
one.

The module only reports. What to do with it (logging, scoring, challenging) is
up to the configuration; [`examples/`](examples) shows a few readings in njs.

> **HTTP/3 is not covered.** QUIC runs over UDP: there is no TCP SYN to read,
> and the variables are empty on HTTP/3 requests. A client can pick HTTP/3
> to avoid the fingerprint, so treat an empty `$tcpfp_signature` as
> "unknown", never as "clean".

## Variables

| variable | value |
|---|---|
| `$tcpfp_signature` | everything below in one string, laid out like p0f v3 raw signatures: `ver:ttl+hops:olen:mss:wsize,scale:options:quirks:pclass`, e.g. `4:116+12:0:1460:mss*44,8:mss,nop,ws,nop,nop,sok:df:0` |
| `$tcpfp_ttl` | TTL (IPv4) or hop limit (IPv6) the SYN arrived with, e.g. `116` |
| `$tcpfp_ittl` | initial TTL guessed from it: 32, 64, 128 or 255 |
| `$tcpfp_hops` | `$tcpfp_ittl` minus `$tcpfp_ttl` |
| `$tcpfp_win` | TCP window |
| `$tcpfp_mss` | MSS option, empty without one |
| `$tcpfp_wscale` | window scale option, empty without one |
| `$tcpfp_options` | option layout, in order: `mss`, `ws`, `sok` (SACK permitted), `sack`, `ts`, `nop`, `eol+N` (end of options and N padding bytes), `?K` (unknown kind K) |
| `$tcpfp_quirks` | oddities of the headers, empty when none (below) |
| `$tcpfp_tls_rtt` | TLS 1.3 handshake round trip in microseconds: from the server's Finished sent to the client's Finished read |
| `$tcpfp_tcp_rtt` | the kernel's smoothed TCP RTT (`tcpi_rtt`) in microseconds, read when the client's Finished arrived |

In the signature, `olen` is the length of the IPv4 options, `wsize` the window
written as a multiple of the MSS (`mss*44`) or of the MTU (`mtu*4`) when it is
one, `mss` and `scale` are 0 when the option is absent (the layout says
which), and `pclass` is `+` when the SYN carries data (TCP Fast Open), `0`
otherwise.

Quirks, in this order:

| quirk | meaning |
|---|---|
| `df` | IPv4 "don't fragment" |
| `id+` | DF with a non-zero IP ID |
| `id-` | no DF and a zero IP ID |
| `ecn` | ECN bits in the IP header, or ECE/CWR in the SYN |
| `0+` | IPv4 reserved ("must be zero") flag set |
| `flow` | non-zero IPv6 flow label |
| `seq-` | zero sequence number |
| `ack+` | non-zero ACK number without the ACK flag |
| `ack-` | ACK flag with a zero ACK number |
| `uptr+` | non-zero urgent pointer without the URG flag |
| `urgf+` | URG flag |
| `pushf+` | PSH flag |
| `ts1-` | timestamp option with a zero own timestamp |
| `ts2+` | timestamp option echoing a non-zero peer timestamp |
| `opt+` | non-zero bytes after the end of options |
| `exws` | window scale above 14 |
| `bad` | malformed options |

Typical values:

| client | `$tcpfp_options` | window, scale | initial TTL |
|---|---|---|---|
| Windows 10/11 | `mss,nop,ws,nop,nop,sok` | 64240 (`mss*44`), 8 | 128 |
| Linux, Android | `mss,sok,ts,nop,ws` | 64240, 65535... , 7 | 64 |
| macOS, iOS | `mss,nop,ws,nop,nop,ts,sok,eol+1` | 65535, 6 | 64 |

The TTL is the initial TTL minus the hops: compare it with 64, 128 and 255
rather than for equality, or read `$tcpfp_ittl`.

The SYN variables are empty (not found) when there is no SYN to read: HTTP/3,
`tcp_fingerprint off`, connections accepted before `tcp_fingerprint on` was
loaded, non-TCP listeners.

`$tcpfp_tls_rtt` and `$tcpfp_tcp_rtt` are empty without TLS 1.3 (plain HTTP,
TLS 1.2: the server waits there for the client's key exchange, whose
computation would count), on HTTP/3 and with `tcp_fingerprint off`. The TLS
RTT also counts the client's work on the server's flight (certificate check, a
few milliseconds) and the time the worker takes to read the Finished; a server
flight larger than the initial congestion window (big certificate chain), or a
loss, adds round trips. Compare the two values with a wide margin (ratio and
absolute gap), never for equality. Tunnels that terminate TLS (corporate
gateways that inspect it) show no gap; relays that cut TCP close to a slow last
mile do (mobile networks' transparent TCP proxies, iCloud Private Relay).

## Directive

```
Syntax:  tcp_fingerprint on | off;
Default: tcp_fingerprint off;
Context: http, stream
```

Turns on `TCP_SAVE_SYN` on every TCP socket the containing `http` or `stream`
block listens on.
Loading the module without `tcp_fingerprint on` changes nothing: `off` leaves
the sockets alone, so it never undoes another module that reads the SYN. A
listening socket kept across a reload from `on` to `off` goes on saving SYNs
(about 100 bytes per connection, freed when it closes) until nginx restarts.

## Example

```nginx
load_module modules/ngx_http_tcp_fingerprint_module.so;
load_module modules/ngx_stream_tcp_fingerprint_module.so;

http {
    tcp_fingerprint on;

    log_format fp '$remote_addr "$http_user_agent" sig=$tcpfp_signature '
                  'tls_rtt=$tcpfp_tls_rtt tcp_rtt=$tcpfp_tcp_rtt';

    server {
        listen 443 ssl;
        http2 on;
        access_log /var/log/nginx/fp.log fp;

        location / {
            # hand it to an auth_request / njs / backend that scores it
            proxy_set_header X-TCP-Signature $tcpfp_signature;
            proxy_pass http://backend;
        }
    }
}
stream {
    tcp_fingerprint on;
    log_format fp '$remote_addr sig=$tcpfp_signature '
                  'tls_rtt=$tcpfp_tls_rtt tcp_rtt=$tcpfp_tcp_rtt';
    access_log /var/log/nginx/stream-fp.log fp;

    server {
        listen 8443 ssl;
        ssl_certificate server.crt;
        ssl_certificate_key server.key;
        proxy_pass backend:9000;
    }
}
```

The SYN variables also work on plain TCP listeners. RTT measurements require
local TLS 1.3 termination; TLS passthrough with `ssl_preread` has no RTT sample.
UDP and Unix-domain listeners return empty variables.

## njs examples

[`examples/tcpfp.js`](examples/tcpfp.js) reads `$tcpfp_signature` and gives
hints, with [`examples/nginx.conf`](examples/nginx.conf) to wire them:

- `stackOs` / `osMismatch`: the system of the stack against the one of the
  User-Agent (Windows or Mac UA on a Linux stack).
- `link`: the link the MSS points to: Ethernet, PPPoE, IP tunnel (6rd, 6in4),
  GRE, WireGuard, jumbo frames (datacenter hosts), or reduced (VPNs, mobile
  carriers' clamping).
- `crafted`: a SYN no ordinary stack sends (raw socket scanners).
- `tunnelled`: TLS round trip well above the TCP one.
- `stacksBehind`: several systems behind one address (NAT, proxy pool), in a
  shared dictionary.

They are hints, not verdicts. Corporate gateways (Zscaler, Netskope,
Forcepoint) and university networks rewrite TCP on Linux boxes, mobile
carriers clamp the MSS, VPNs and iCloud Private Relay change everything: real
visitors show every one of them. Measure them on your own traffic, add them
to a score with other signals, and never block on one alone.

## How it works

- At each configuration load, the master process sets `TCP_SAVE_SYN` on the
  listening sockets. Accepted connections inherit it: the kernel keeps a copy
  of each connection's SYN (IP and TCP headers, about 100 bytes) until it is
  read or the connection closes.
- The first request that reads a variable on a connection fetches the SYN
  with `getsockopt(TCP_SAVED_SYN)` (one system call per connection, the kernel
  frees its copy), parses it, and keeps the result in the connection's memory
  pool. Keepalive requests and HTTP/2 streams reuse it.
- After that, a request costs no system call and no allocation. Parsing is
  bounds-checked against the length the kernel returns.
- With `tcp_fingerprint on`, the module sets an OpenSSL message callback on
  the SSL context of every `server` (SSL connections keep it when SNI switches
  context). It notes the time the server's Finished is written, and when the
  client's is read, computes the TLS RTT, reads `getsockopt(TCP_INFO)`, keeps
  both in the connection's pool and removes itself from the connection: no
  cost once the handshake is over.

## Requirements

- Linux 4.2 or later (`TCP_SAVE_SYN`).
- OpenSSL 1.1.1 or later for the TLS RTT (TLS 1.3).
- nginx built with `--with-compat` for a dynamic module. Tested with nginx
  1.31.7.
- The client's SYN must reach nginx unchanged: behind a load balancer, a
  proxy or a NAT that terminates TCP, you get the fingerprint of that box.

## Build

```sh
# dynamic module, against the sources of the nginx you run
cd nginx-1.x.y
./configure --with-compat --add-dynamic-module=/path/to/ngx-tcp-fingerprint
make modules
cp objs/ngx_http_tcp_fingerprint_module.so /usr/lib/nginx/modules/
```

Add `--with-stream --with-stream_ssl_module` to build
`ngx_stream_tcp_fingerprint_module.so` as well. Each module can be loaded
independently. With `--with-stream=dynamic`, load `ngx_stream_module.so`
first. `--without-http --with-stream` builds only the Stream module;
`--add-module` supports static builds.

## Tests

```sh
sudo t/test.sh 1.31.7
```

Builds nginx with the module (`-Werror`), then checks the variables against
real SYNs in throwaway network namespaces, where TCP sysctls change the
client's SYN: Linux defaults, no timestamps, MSS only, TTL 100 and 128, ECN,
IPv6 hop limit and flow label, keepalive, HTTP/2, `tcp_fingerprint off`. For
the RTTs, netem delays the loopback: a direct client at 20 ms (both values
close), a client behind a TCP relay with the delay on its side only (TLS RTT
60 ms, TCP RTT near zero), one handshake for HTTP/2 streams, nothing on
TLS 1.2 or plain HTTP. With the `njs` command line, it also runs
`t/examples.js` on the examples.

## Versions

Releases are `vX.Y.Z` tags ([Semantic Versioning](https://semver.org/)),
listed in [CHANGELOG.md](CHANGELOG.md) and on the
[releases page](https://github.com/studio-vitalyn/ngx-tcp-fingerprint/releases).
Until 1.0.0, a minor version may rename or change variables. Build from a
tag, not from `main`.

To release: add the version's section to `CHANGELOG.md`, commit, then push
the tag (`git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0`). The
`release` workflow runs the tests and publishes the release with that
section as its notes; a tag without a section fails.

## License

[BSD 2-Clause](LICENSE), like nginx.
