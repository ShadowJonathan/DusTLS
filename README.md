# `dustls`, a pure-rust DTLS implementation

A DTLS implementation in Rust, reusing [`rustls`](https://github.com/rustls/rustls) for cryptographic primitives and most message payload formats.

Currently targetting a PoC for DTLSv1.2, v1.3 will come after that. No plans to support DTLSv1.0.

**Note: This library is a work in progress, and (possibly) not yet tuned to the ecosystem.**

**Note: This library directly works with TLS records, logic, and Cipher Suites, and hasn't had a security audit (yet), use at your own risk.**
