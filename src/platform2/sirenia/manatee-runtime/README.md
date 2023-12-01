# manatee-runtime

`manatee-runtime` provides the TEE app facing API that provides functionality
such as storage and secret derivation.

## Creating a new TEE app

Instructions for creating a new TEE application and having it installed along
with the ManaTEE environment.

### Add TEE app

Create a new file in `platform2/sirenia/manatee-runtime/src`. The convention
for naming is `name-of-app.rs`. For an example application see: `demo-app.rs`.
The necessary pieces of a TEE app are as follows:

```rust
use std::borrow::{Borrow, BorrowMut};
use std::io;

use manatee_runtime::storage::TrichechusStorage;
use manatee_runtime::{ExclusiveScopedData, ScopedData};

/*
 * A callback function for when the id is not found in the backing store.
 */
fn callback(s: &str) -> String {
    <callback contents>
}

/*
 * The main body of the TEE app that will be run when started by Trichechus.
 */
fn main() {
    let mut buffer = String::new();

    // Initialize the storage object that allows writing to the backing store through Trichechus.
    let mut store = TrichechusStorage::new();

    // Creating a new scoped data that is backed by storage on Chrome OS. The data will be
    // written back to Chrome OS when flush is called or the data goes out of scope.
    let mut data: ExclusiveScopedData<String, TrichechusStorage> =
        ScopedData::new(&mut store, "<data_id>", callback).unwrap();

    // Borrow the scoped data itself for usage and mutation.
    let s: &mut String = data.borrow_mut();

    // Reading from stdin reads from the pipe connected to the calling process that requested
    // startup from Dugong on Chrome OS.
    let line = io::stdin().read_line(&mut buffer);

    // Outputting to stdout writes to the pipe connected to the calling process that requested TEE
    // startup from Dugong on Chrome OS.
    print!("<message>");
}

```

Add [app manifest entry] for new tee app in `sirenia/src/app_info/mod.rs`. For
now, the feature is still in development, so scope and domain can be `Test` and
`"test"`.

```rust
manifest.add_app_manifest_entry(AppManifestEntry {
   app_name: "<app_name>".to_string(),
   scope: Scope::<System|Session|Test>,
   path: "/usr/bin/demo_app".to_string(),
   domain: "<domain_name>".to_string(),
   sandbox_type: SandboxType::<Container|DeveloperEnvironment|VirtualMachine>,
});
```

Add the binary to the [Cargo.toml].

```toml
[[bin]]
name = "<app_name>"
path = "src/<app-name>.rs"
```

### Add app to ebuild

In order for the app to actually show up on the system, it needs to be installed
via the `manatee-runtime` [ebuild]. All of the logic is already in place to
install it into the right location (the install location depends on whether it
is a manatee build or not) and install lines for the new app just need to be
added to each place the `demo-app` is installed.

```sh
if use manatee ;  then
	doexe "${build_dir}/demo_app"
+	doexe "${build_dir}/<your_app_name>"
else
	dobin "${build_dir}/demo_app"
+	dobin "${build_dir}/<your_app_name>"
fi
```

## ManaTEE Runtime API

This library is the API endpoint for TEE applications to communicate with
Trichechus.

### Storage APIs

The main feature provided by this library is storage capabilities. This library
offers abstractions for reading and writing data via scoped data, a key value
store, or raw APIs.

#### Raw APIs

This includes `read_raw` and `write_raw` that can be used to read and write
data to the ManaTEE backing store.

#### ScopedData

This reads the data into a local store on construction and writes it back on
flush or drop.

#### Scoped Key Value API

This reads in an entire key value store on construction and writes it back on
flush or drop.

[Cargo.toml]: /sirenia/manatee-runtime/Cargo.toml#8
[app manifest entry]: /sirenia/src/app_info/mod.rs#70
[ebuild]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/chromeos-base/manatee-runtime/manatee-runtime-9999.ebuild#44
