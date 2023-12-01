# resourced::VM_GRPC - GRPC support for select ChromeOS boards

This module adds select GRPC API support to resourced.  The GRPCs are used to call the guest VM over VSOCK on projects: hades/draco/agah. For detailed design of the GRPC's, visit internal site: [go/resourced-grpcs](http://go/resourced-grpcs).  The standard `grpcio` rust crate does not support GRPC over vsock.  `grpcio-sys` crate is patched to support vsock over GRPC (ebuild pending).

# Usage and Installation

VM_GRPC is disabled on resourced build by default.  To enable it, build resourced with the feature enabled:
```bash
(inside chroot) platform2/resourced$ cargo build --features vm_grpc
```
Once the target is built, manually copy over `resourced` to DUT.
* Copy resourced to DUT into a directory with exec permission
```bash
(inside chroot) platform2/resourced$ scp target/debug/resourced $DUT://usr/local/sbin
```
* Stop any existing resourced daemon and run resourced with GRPC support
```bash
(on DUT shell)$ sudo stop resourced
(on DUT shell) /usr/local/sbin$ ./resourced
```
* Start Borealis VM or send a dbus `VmStartedSignal` message to start up resourced GRPC server/client pair
```bash
(on DUT shell)$ dbus-send --system --type=signal /org/chromium/VmConcierge org.chromium.VmConcierge.VmStartedSignal
```
</br>

#### Guest VM GRPC Stub
The code contains a mock gRPC client to mimic GRPC interaction on the guest VM side.  To build the client stub, use:
```bash
(inside chroot) platform2/resourced$ cargo build --example test_client_v1 --features="vm_grpc"
```
This will biild a test client for the v1 API in `target/debug/examples/test_client_v1`.  The excutable can be copied into the guest VM and will work in conjunction with the resourced host-side GRPC server.
</br>

# Proto
The proto directory contains `resource_bridge.proto`, which defines all the interfaces and GRPC API calls supported by the server.  It also has definitions of client calls the host side resourced can make.  The other files in the directory are auto generated, can can be created using the `protoc_grpcio` crate and a `build.rs` script that contains:
```rust
let proto_root = "src/vm_bridge/proto/";
protoc_grpcio::compile_grpc_protos(
        &["resourced_bridge.proto"],
        &[proto_root],
        &proto_root,
        None,
    )
```
# Known Issues

* ebuild support is for this feature is pending.
* `grpcio-sys` uses `libstdc++.so.6`, which isn't available on ChromeOS.  Can be temporarily bypassed by copying over `libstdc++.so.6` from build system to `$DUT://usr/lib64/`.
