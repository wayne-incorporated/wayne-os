# ManaTEE Runtime Environment

This [platform2] subproject includes the ManaTEE runtime environment ([`sirenia`]),
the middleware for ManaTEE apps ([`manatee-runtime`]), and the API for communicating
with ManaTEE from Chrome OS ([`manatee-client`]).

For tips and guidance on developing [`sirenia`] see the [`sirenia` developer guide].
The shared code for the various sub-modules mostly is located in [`libsirenia`].

For tips and guidance on writing TEE apps see [creating a new TEE app].

Ebuild dependencies to include:
  * For Chrome OS use [`manatee-client`]:
    * `dev-rust/manatee-client` for **Rust**.
    * `chromeos-base/manatee-client` for **C++**.
  * For **TEE applications** use
[`chromeos-base/manatee-runtime`][`manatee-runtime`].

## Sirenia

`sirenia` makes up the bulk of the ManaTEE runtime code. It is named after the
taxonomic family manatees belong to. It provides the support for running
TEE applications, providing them with storage and crypto APIs, and a
communication channel with the OS. The 2 main components of sirenia are the
hypervisor daemon [`trichechus`], and the Chrome OS guest daemon [`dugong`].

### Trichechus

`trichechus` is the TEE application life-cycle manager. It is named after the
genus manatees belong to. It serves the following purposes related to TEE
applications:

1. Loading and validation
2. Instance management
   - Establishing communication
   - Launching
   - Sandboxing
   - Cleaning up
3. Serving the app with APIs
   - Storage
   - Derived Secrets
4. Logging and (TODO) crash dump collection

### Dugong

`dugong` is the broker daemon on Chrome OS that communicates with Trichechus.
It is named after the cousin genus to manatees since this runs on the Chrome OS
guest, but is closely related to ManaTEE and Trichechus. Dugong implements the
[`org.chromium.ManaTEEInterface`] D-Bus interface as the `org.chromium.ManaTEE`
end point. This facilitates Chrome OS services sending requests to
[`trichechus`].

Its roles include:

1. Validating permissions. This is mostly delegated to D-Bus by exposing sub
   interfaces for each TEE app. Access control to these interfaces is enforced
   by the [D-Bus access policy].
2. Fetching TEE app binaries for [`trichechus`].
3. Routing log events and (TODO) crash reports.

***note
**Note:** per TEE app interfaces are programmatically implemented at
`org.chromium.manatee.<app_dbus_identifier>` where `<app_dbus_identifier>`
is the app name registered in the app-info manifest with any hyphens `-`
replaced with underscores `_` for compatibility. This allows for
per app D-Bus policies to be written for access control similar to the
general [D-Bus access policy].

The interface description can be found in the
`register_dbus_interface_for_app` function in [`dugong.rs`]
***

### tee_app_info_lint

This is a tool for linting and converting TEE app-info manifest entries.
Digests are sometimes included in manifest entries, so the linter provides some
functionality to help populate these digests at build time.

Here are some examples for populating the digest for:
* A binary installed to the root-fs:
  * Manifest entry: [demo-app.json]
* A binary installed through [DLC]:
  * Manifest entry: [`termina.json.in`]
  * [`termina-dlc` ebuild]

### Internal Modules

Sirenia includes a few modules of library code specific to [`dugong`] and/or
[`trichechus`]. These modules include:

**app-info:** TEE app-info manifest handling logic.

**secrets:** Secret derivation logic.

[creating a new TEE app]: ./manatee-runtime/README.md#Creating-a-new-TEE-app
[D-Bus access policy]: ./dbus/org.chromium.ManaTEE.conf
[demo-app.json]: ./manatee-runtime/src/demo-app.json
[DLC]: ../dlcservice/README.md
[`dugong`]: #Dugong
[`dugong.rs`]: ./src/dugong.rs
[`libsirenia`]: ./libsirenia/README.md
[`manatee-client`]: ./manatee-client/README.md
[`manatee-runtime`]: ./manatee-runtime/README.md
[`org.chromium.ManaTEEInterface`]: ./dbus_bindings/org.chromium.ManaTEE1.xml
[platform2]: /README.md
[`sirenia`]: #Sirenia
[`sirenia` developer guide]: RUNNING_SIRENIA.md
[`termina.json.in`]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/chromeos-base/termina-dlc/files/termina.json.in
[`termina-dlc` ebuild]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/chromeos-base/termina-dlc/termina-dlc-9999.ebuild
[`trichechus`]: #Trichechus
