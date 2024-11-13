# Rusty Dns

Explorative project written for practicing Rust, the [Tokio](https://tokio.rs/) echosystem and learning abount the application layer and dns.
Inspired by this awesome projects:
- [dnsguide](https://github.com/EmilHernvall/dnsguide/blob/master/README.md)
- [zero-to-production](https://github.com/LukeMathWalker/zero-to-production)

This is just a toy project and should not be used into production.


# Usage

```bash
cd <ROOT_DIRECTORY>
cargo run
```

to test:

```bash
dig @127.0.0.1 -p 5000 wiki.archlinux.org
```

