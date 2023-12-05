# Passing Chrome flags from `session_manager`

## Runtime configuration

Chrome sometimes needs to behave differently on different Chrome OS devices.
It's preferable to test for the hardware features that you care about directly
within Chrome: if you want to do something special on Chromebooks that have
accelerometers, just check if an accelerometer device is present.

## Build-time configuration

Sometimes it's not possible to check for these features from within Chrome,
though. In that case, the recommended approach is to add a command-line flag to
Chrome and update `session_manager` to pass it with the appropriate value (if
any).

Chrome's command line is constructed by [chrome_setup.cc]. This file uses the
[ChromiumCommandBuilder] class from `libchromeos-ui` to create directories
needed by Chrome, configure its environment, and build its command line.

`ChromiumCommandBuilder` reads a subset of the Portage USE flags that were set
when the system was built from `/etc/ui_use_flags.txt`; these can be used to
determine which flags should be passed. To start using a new USE flag (including
a board name), add it to the [libchromeos-use-flags] ebuild file. (Relegating
this file to a tiny dedicated package allows us to use the same prebuilt
`chromeos-chrome` and `chromeos-login` packages on devices that have different
sets of USE flags.)

### Configuration location

Configuration that would apply both to the Chrome browser and to other products
that could be built using the Chromium codebase (e.g. a simple shell that runs a
dedicated web app) should be placed in `ChromiumCommandBuilder`. This includes
most compositor- and audio-related flags.

Configuration that is specific to the Chrome browser should instead be placed in
[chrome_setup.cc]. This includes most flags that are implemented within Chrome's
`//ash` and `//chrome` directories.

### Translating chromeos-config to switches

The preferred way to add model-specific switches to the command line
is to use [chromeos-config] to specify the model specific
configuration.

To do so, no changes to `session_manager` are required.  Simply
generate the corresponding switches in [cros_config_schema] (search
for `AshSwitches`).

### Use feature-based USE flags

If you need a model-specific configuration for a pre-unibuild device
(2016 and before), or you need to apply a feature to experimental
builds, the best way to do this is USE flags.

Note: USE flags are not able to introduce model-specific switches in
the unibuild world.

If possible, introduce a new USE flag named after the feature that you're adding
and set it in the appropriate [board overlays] rather than making
`session_manager` examine board USE flags like `samus` or `eve`. Using
feature-specific USE flags reduces the number of changes needed to enable the
feature for a new board — just set the USE flag in the new board's overlay. In
contrast, if `session_manager` contains an expression like this:

```c++
if (builder->UseFlagIsSet("samus") || builder->UseFlagIsSet("eve"))
  builder->AddArgs("--enable-my-feature");
```

then additionally enabling the feature for `newboard` will require:

*   Adding `newboard` to `IUSE` in [libchromeos-use-flags] if it's not there
    already
*   Updating `session_manager` to additionally check for the `newboard` USE flag

## Making quick changes

[/etc/chrome_dev.conf] can be modified on dev-mode Chrome OS systems (after
making the root partition writable) to add or remove flags from Chrome's command
line or modify Chrome's environment. The file contains documentation about its
format.

[chrome_setup.cc]: ../chrome_setup.cc
[ChromiumCommandBuilder]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/libchromeos-ui/chromeos/ui/chromium_command_builder.h
[libchromeos-use-flags]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/chromeos-base/libchromeos-use-flags/libchromeos-use-flags-9999.ebuild
[board overlays]: https://chromium.googlesource.com/chromiumos/overlays/board-overlays/+/HEAD
[chromeos-config]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/chromeos-config/
[cros_config_schema]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/chromeos-config/cros_config_host/cros_config_schema.py
[/etc/chrome_dev.conf]: ../chrome_dev.conf
