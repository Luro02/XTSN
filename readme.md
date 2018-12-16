### AES-XTS with Nintendo ported for Rust
Well it's based on switchfs and took me quite some time to port.

### Issues:
- the Rust-Version of XTSN.encrypt is broken (Python base is broken too)
-> using the C-version :3
