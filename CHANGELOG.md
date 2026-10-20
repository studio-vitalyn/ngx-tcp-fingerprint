# Changelog

Versions follow [Semantic Versioning](https://semver.org/). Until 1.0.0,
a minor version may rename or change variables; the changes are listed
here. Each version is a `vX.Y.Z` tag, released on GitHub with the notes of
its section below.

## Unreleased

- Add Stream support for `tcp_fingerprint` and all `$tcpfp_*` variables.

## 0.1.0 - 2026-10-15

First release.

- `tcp_fingerprint on|off` (http): saves the SYN of each connection on the
  HTTP listening sockets (`TCP_SAVE_SYN`).
- `$tcpfp_signature`: the SYN in the layout of p0f v3 raw signatures,
  `ver:ttl+hops:olen:mss:wsize,scale:options:quirks:pclass`.
- Each field on its own: `$tcpfp_ttl`, `$tcpfp_ittl`, `$tcpfp_hops`,
  `$tcpfp_win`, `$tcpfp_mss`, `$tcpfp_wscale`, `$tcpfp_options`,
  `$tcpfp_quirks`.
- `$tcpfp_tls_rtt` and `$tcpfp_tcp_rtt`: TLS 1.3 handshake round trip next
  to the kernel's TCP RTT.
- `examples/`: njs readings of the signature (stack vs User-Agent system,
  link type from the MSS, hand-built SYNs, RTT gap, several stacks behind
  one address).
- Tested with nginx 1.31.7 on Linux.
