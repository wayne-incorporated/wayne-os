# libsirenia

The main library code for [`sirenia`] that is more general and useful for all parts
of [`sirenia`]. These modules include:

**Cli:** Provides commonly used functionality for the command line invocation of
[`dugong`], [`trichechus`], and the [`manatee` command line tool].

**Communication:** General communication code that handles sending over a
connection and serialization and deserialization. It also includes RPC
specifications in the form of Rust traits.

**Linux:** All Linux specific code that is necessary for Sirenia. This includes
events, which provides support for using EventMultiplexer, and syslog which
provides a lite syslog receiver.

**RPC:** Abstractions used to implement remote-procedure-calls on-top of the
`communication` and `linux::event` modules. Also see [`sirenia-rpc-macros`]
which provides a procedural macro for automatically implementing the RPC
boilerplate given a Rust trait.

**Sandbox:** Support code for using VMs or containers to sandbox TEE
applications.

**Storage:** Abstractions used to back the TEE app storage API.

**Sys:** Low-level libc functionality that does not belong in the crosvm-base
crate.

**Transport:** Abstractions over a combination of Rust traits needed to
generalize the `linux::event` and `communication` modules for VSOCK, IP,
and file descriptor pairs such as a pipes.

[`dugong`]: ../README.md#Dugong
[`manatee` command line tool]: ../manatee-client/README.md#Manatee-command-line-tool
[`sirenia`]: ../README.md
[`sirenia-rpc-macros`]: ./sirenia-rpc-macros/README.md
[`trichechus`]: ../README.md#Trichechus
