# Featured Rust wrapper

Note: This crate is specific to ChromeOS and requires the native
[libfeatures_c](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/featured)
library at link time.

`featured-rs` is a Rust wrapper for libfeatures_c. This library is used to interact with Featured to check
which features are currently enabled.

## Building for the host environment

You can also execute `cargo` directly for faster build and tests. This would be useful when you are
developing this crate. Since this crate depends on libfeatures_c.so, you need to install it to host
environment first.

```shell
# Install libfeatures_c.so to host.
(chroot)$ sudo emerge chromeos-base/featured
# Build
(chroot)$ cargo build
# Unit tests
(chroot)$ cargo test
```

## Generated bindings

The build script, `build_buildings.sh`, generates bindings to `../c_feature_library.h`.
Whenever breaking changes are made to `../c_featured_library.h`, this build script must be
rerun to generate new bindings to the C library.

## Running the examples on DUT

First, you need to make sure you have deployed `featured` to your DUT.
You may also need to deploy `libchrome` and `libbrillo` to have the examples run properly.

```shell
(chroot)$ cros deploy ${DUT_IP} chromeos-base/featured
```

Second, you need to build them and copy them over to your device.

```shell
(chroot)$ cargo build --release --examples
(chroot)$ scp target/release/examples/*feature_check $DUT:/usr/local/bin
```

To run them on your DUT:

```shell
(DUT)$ feature_check
(DUT)$ fake_feature_check
```
