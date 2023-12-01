The UWB D-Bus Daemon
====================

This repository implements the UWB D-Bus daemon, including the service written
in Rust, the D-Bus and upstart configuration files, D-Bus interface and
protobuf definition. The D-Bus daemon defines the D-Bus interface, initiates
the UWB service from the uwb\_core library, and delegates the requests to the
UWB service.

# Development Flow

Officially, this project is built by ChromeOS gentoo build system. However, the
D-Bus daemon binary could also be built by cargo. Building the rust code by
cargo could validate whether the code is compilable quickly.

## Built by Gentoo

It follows the normal ChromeOS development flow.

```
(inside chroot)
$ cros-workon-<board> uwbd
$ emerge-<board> uwbd
```

## Built by Cargo

THe `uwb_uci_packets` packet, which is a dependency of the D-Bus daemon, depends
on the `bluetooth_packetgen` binary. So we should install the
`bluetooth_packetgen` binary before building the D-Bus daemon by cargo.

```
(inside chroot)
$ sudo emerge floss_tools
$ cargo build
```

# HAL Implementation

When initiating the UWB service from the uwb\_core library, we need to inject
the UCI HAL into it. The HAL implementation should be placed at `src/uci_hal_impl.rs`.

# File Structure

- dbus: D-Bus policy configuration
- dbus\_bindings: D-Bus interface xml
- protos: The protobuf message definition
- src: The rust implementation
- upstart: The upstart configuration
