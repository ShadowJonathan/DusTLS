# `dustls`, a pure-rust DTLS implementation

# Note: this project is on hiatus, there is a small chance i might return to it, but for now i need to worry about a lot of other things, so i might not have time to work on this for a while.

### Take inspiration from the existing code and issues, and if you want to take over the project, create an issue or poke me wherever.

A DTLSv1.2 implementation in Rust, reusing [`rustls`](https://github.com/rustls/rustls) for cryptographic primitives and most message payload formats.

**Note: This library is a work in progress, and (possibly) not yet tuned to the ecosystem.**

**Note: This library directly works with TLS records, logic, and Cipher Suites, and hasn't had a security audit (yet), use at your own risk.**
