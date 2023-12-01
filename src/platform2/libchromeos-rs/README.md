# libchromeos-rs - The Rust crate for common Chrome OS code

`libchromeos-rs` contains Rust code that can be reused across any Chrome OS
project. It's the Rust equivalent of [libbrillo](../libbrillo/).

Current modules include:
* `syslog` - an adaptor for using the generic `log` crate with syslog
* `vsock` - wrappers for dealing with AF_VSOCK sockets
