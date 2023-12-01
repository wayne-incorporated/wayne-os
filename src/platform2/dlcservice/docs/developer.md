# DLC Developer Guide

A guide on how to get up and running with a DownLoadable Content (DLC).

[go/dlc-framework] to see if DLC is right the right use case. (If you already
know enough about DLCs and is a clear solution for you, please jump right in)

## Introduction

DLC allows ChromeOS developers to ship a feature (e.g. a ebuild/package) to
stateful partition as packages (ebuilds) and provides a way to download at
runtime.

*   **Development** Developers should follow [Development Steps].
*   **Location** Most packages usually install to the root filesystem.
    DLCs are downloaded at runtime to the stateful partition and only install
    verifiable data (metadata) into the root filesystem.
*   **Install/Update** Packages installed into the root filesystem will always
    be installed and updated with ChromeOS. DLCs can be installed on demand and
    are updated atomically with ChromeOS only if installed. All DLC
    installations are handled by [dlcservice].
*   **Payloads/Artifacts** The DLC infrastructure automatically handles
    all packaging, hosting, and serving of DLC payloads.

## Development Steps

The steps for developing a DLC involves the following:

* [Create a DLC]
* [Building a DLC locally]
* [Enabling a DLC]
* [Install/Uninstall a DLC]
* [Write tests dependant on a DLC]

### Create a DLC

A DLC involves adding a portage package (ebuild). The package file should
inherit [dlc.eclass].<br>
(Note: modifying a DLC requires upreving the package)

__See an example DLC:__ [scaled-dlc ebuild]

Within the package, must include the `src_install` function to install the DLC
content using a special path prefix set by `$(dlc_add_path )`. This means, that
before installing any DLC files, you have to add the dlc prefix path to
`into, insinto` and `exeinto` using `$(dlc_add_path your_path)`. Always call
`dlc_src_install` at the end of your `src_install` function to pack the DLC.

The following variables must/can be set:

#### Required:

*   `DLC_PREALLOC_BLOCKS` - The number of blocks to reserve for A/B copies of a
    DLC. Each block is 4KiB. It is necessary to set this value more than the
    minimum required to accommodate future size growth (recommendation is 130%
    of the DLC size).<br>
    (Note: This is the required number of blocks should be calculated *AFTER*
    contents of a DLC is compressed. TODO(kimjae): Create tool here to ease
    calculation.)
*   `DLC_SCALED` - All new DLCs should be scaled. In the future this value will
    be on by default. __Please set this to `true`.__

#### Optional (Please skip over these or read if curious):

*   `DLC_ID` - The unique ID, requirements:
     *    It should not be empty.
     *    It should only contain alphanumeric characters (a-zA-Z0-9) and `-`
          (dash).
     *    The first letter cannot be dash.
     *    No underscore.
     *    It has a maximum length of 80 characters.
     (Note: Should almost never be manually set, unless the intent is to create
     a multi-package DLC, which is not recommended)
    (Default is `${PN}`)
*   `DLC_DESCRIPTION` - Human reable description of the package.
    Override iff the default `${DESCRIPTION}` is not enough to describe purpose.
    (Default is `${DESCRIPTION}`)
*   `DLC_PACKAGE` - *deprecated*, do not use.
    (Default is `package`)
*   `DLC_NAME` - Name of the DLC.
    It is for description/info purpose only.
    (Default is `${PN}`)
*   `DLC_VERSION` - Version of the DLC.
    It is for description/info purpose only.
    (Default is `${PVR}`)
*   `DLC_PRELOAD` - Preload the DLC.
    When set to true, the DLC will be preloaded (pre-installed) for test images.
    Should only be set if tast/tauto tests run for features depending on the
    DLC.
    (Default is false)
*   `DLC_ENABLED` - Override being a DLC.
    When set to false, `$(dlc_add_path)` will not modify the path and everything
    will be installed into the rootfs instead of the DLC path. This allows the
    use of the same ebuild file to create a DLC under special conditions (i.e.
    Make a package a DLC for certain boards or install in rootfs for others).
    (Default is true)

### Building a DLC locally

Installing a DLC on a device is similar to installing a portage package
(ebuild):

*   Emerge the package: `emerge-${BOARD} <DLC_ID>`
*   Pack the DLC and deploy over to the device:
    `cros deploy ${IP} <DLC_ID>`

### Enabling a DLC

Once your ready to enable your DLC, you can target enabling the DLC package
selectively behind your own USE flags or at the top level [target-chromium-os]
package to be enabled across all ChromeOS devices behind the main `dlc` USE
flag.

Note: if you need to enable a DLC selectively per board, you must do so using
your own USE flag.

### Install/Uninstall a DLC

Permitted ash chrome or system daemons that can access D-Bus can call dlcservice
APIs to install/uninstall a DLC.

*   For calling the dlcservice API inside ash chrome, use [dlcservice_client].
*   For calling dlcservice API outside of ash chrome, use generated D-Bus
    bindings.

A DLC is downloaded and installed at runtime by dlcservice and will return a
root mount path for the DLC when installed.<br>
__This root mount path should \*\*NEVER\*\* be hardcoded/cached/persisted across
reboots.__

This warrants always requesting to install the DLC before use at all times. The
DLC will remain mounted as long as the device or UI (ash chrome) does not
restart. It is completely up to dlcservice to return any type of root mount
paths in the future, but the root will always be suffixed at `/run/imageloader`.

If your service/daemon uses minijail, you will have to:
*   Recursively bind mount (`MS_BIND|MS_REC`) `/run/imageloader/` by passing the
    parameter `-k` to minijail.
*   Set the parameters `-v -Kslave` to allow propagation of the mount namespace
    of the mounted DLC image to your service.
*   Depending on your seccomp filters, you might have to include additional
    permissions. Please refer to [sandboxing].

If your service/daemon also starts on `starting system-services`:
*   Please add an additional stanza that says `and stopped imageloader-init`.

On a locally built test build|image, calling dlcservice API does not download
the DLC (no DLC is being served), unless the DLC is preloaded using
[Write tests dependant on a DLC]. For local development, please follow
[Building a DLC locally].

### Write tests dependant on a DLC

In order to test a DLC dependant feature, the optional variable field
`DLC_PRELOAD` needs to be set to true while the integration/tast tests invoke
installing the DLC. This will allow tests to seamlessly install the DLC on test
images.

There is ongoing effort to tie DLC provisioning into the ChromeOS test run as
part of OS provisioning. Also, there are gRPC services that tast/tauto tests can
directly invoke to provision a DLC - there however isn't a client that nicely
wraps all of this for the test writer at the moment.

## Frequently Asked Questions

### How do I set up the DLC download server (upload artifacts, manage releases, etc.)?

You don't, our infrastructure will handle all this for you.

### Can I release my DLC at my own schedule?

This is fundamentally not possible with DLCs, just as developers are tied to
release process, DLCs are too.

Note: in the case of scaled DLCs, all release builds can install the DLC OTA,
while legacy DLCs are strictly tied to releases that go live.

### How do I update my DLC?

Modifying a DLC is the same as modifying a portage package (ebuild).
A DLC is updated at the same time the device itself is updated.

Note: in the case of scaled DLCs, it will not update with the OS at the moment.

### How to install from production servers from a test image when my DLC is preloaded?

If you are using a developer-built image, you cannot easily install DLC from
production servers.
Instead, you should use preloading or deploy the DLC package.

The DLC that has preloading enabled must first be uninstalled.
Uninstall the DLC using the utility binary:
`dlcservice_util --uninstall --id=<DLC_ID>`.

Next step is to wipe the preloaded DLC on your test image device.
You can remove the preloaded directory for your DLC at
`/var/cache/dlc-images/<DLC_ID>`.

If your DLC is a scaled DLC, you can proceed with the DLC installation and be
on your way.

If your DLC is a legacy DLC, you must modify your ChromeOS lsb-release to fake
being a signed device. This must be done by disabling rootfs verification and
adding a `-signed` suffix to the key `CHROMEOS_RELEASE_BOARD`.

e.g. the key should look like `CHROMEOS_RELEASE_BOARD=<BOARD>-signed`.

Also, for legacy DLCs, this will only work for "live" images
(ChromeOS builds that were pushed).

[Development Steps]: #Development-Steps
[Create a DLC]: #Create-a-DLC
[Building a DLC locally]: #Building-a-DLC-locally
[Enabling a DLC]: #Enabling-a-DLC
[Install/Uninstall a DLC]: #Install_Uninstall-a-DLC
[Write tests dependant on a DLC]: #Write-tests-dependant-on-a-DLC

[go/dlc-framework]: http://go/dlc-framework
[dlcservice]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/dlcservice
[dlc.eclass]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/dlc.eclass
[sandboxing]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/sandboxing.md
[overlay-eve make.defaults]: https://chromium.googlesource.com/chromiumos/overlays/board-overlays/+/HEAD/overlay-eve/profiles/base/make.defaults
[dlcservice_client]: https://chromium.googlesource.com/chromium/src/+/main/chromeos/ash/components/dbus/dlcservice/dlcservice_client.h
[scaled-dlc ebuild]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/bb1a2bb68f01e70f1ce8bc1b3c6ba9954c73fcda/chromeos-base/scaled-dlc/scaled-dlc-1.0.0.ebuild
[target-chromium-os]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/1664a910b9e7548221063c108f15eacea142c697/virtual/target-chromium-os/target-chromium-os-9999.ebuild
