# ADR-0015: Native TLS (supersedes the v0.1 "no TLS" half of ADR-0004)

Date: 2026-10-02 · Status: ACCEPTED

## Decision
Both planes serve HTTPS via rustls with an auto-generated self-signed cert
(`cert.pem` + `key.pem`, key 0600, 10y, SANs: localhost/127.0.0.1/::1).
Clients pin the cert (TOFU): the CLI auto-trusts `cert.pem` in FARCONTROL_HOME,
override with `FARCONTROL_CA`. `use_tls = false` in config.toml keeps plain
HTTP for loopback-only development. Default URL scheme follows cert presence.

## Consequences
+ Confidentiality on the wire — remote use no longer requires a tunnel.
+ HMAC proof-of-possession still rides on top (defense in depth).
- The cert is enrollment material: distribute token + cert.pem together over
  a trusted channel. Rotation of the cert = delete + restart (documented).
