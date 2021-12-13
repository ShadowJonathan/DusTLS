# `dustls` a pure-rust DTLS implementation

A DTLSv1.2 implementation in Rust, reusing [`rustls`](https://github.com/rustls/rustls) for cryptographic primitives and most message payload formats.

**Note: This library is a work in progress, and (possibly) not yet tuned to the ecosystem.**

**Note: This library directly works with TLS records, logic, and Cipher Suites, and hasn't had a security audit (yet), use at your own risk.**
