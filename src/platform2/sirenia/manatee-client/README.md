# manatee-client

This sub crate provides library functions for communicating with ManaTEE from
Chrome OS. This is implemented as a D-Bus API managed by [`dugong`] which then
communicates with [`trichechus`] over VSOCK.

There is a [`BUILD.gn`](./BUILD.gn) file associated with
`chromeos-base/manatee-client` that generates C++ D-Bus bindings for ManaTEE.

Also there is a Rust crate with its own D-Bus bindings for ManaTEE associated
with `dev-rust/mantee-client`.

## Manatee command line tool

`manatee-client` provides a command line tool `manatee` to provide developer
access to a shell on the hypervisor or other TEE apps. If run with no
arguments, it will try to open a developer shell through [`dugong`].

It can bypass [`dugong`] and open a direct connection to [`trichechus`] using
the `-U` option if [`dugong`] is not already holding the control socket. This
is particularly useful in developer environments where [`dugong`] fails because
it lacks the permissions required to acquire its D-Bus endpoint and interface.

Additionally, `manatee-client` has a `-r` option which sets up a copy of
`cronista`, [`trichechus`], and [`dugong`] over IP on localhost for testing.

[`dugong`]: ../README.md#Dugong
[`trichechus`]: ../README.md#Trichechus
