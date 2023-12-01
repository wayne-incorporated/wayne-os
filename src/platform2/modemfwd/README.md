# Modem Firmware Daemon

This daemon abstracts out the common portions of updating modem firmware, i.e.
deciding whether there is currently newer firmware available and getting the
modem ready to be flashed with new firmware.

## Modem-specific program API

In order to enforce a process boundary between the open-source `modemfwd` and
potentially non-open-source modem firmware updaters, we farm out steps that
require modem-specific knowledge to different programs. `modemfwd` will call
into these programs with different flags to request different services. These
flags are declared in the [system API] repo.

* `--get_fw_info`: return version information for the currently installed
  firmware (see below)
* `--prepare_to_flash`: put the modem into firmware download mode
* `--flash_fw=<type>:<file>[,<type2>:<file2>[,<type3>:<file3>]`
* `--flash_mode_check`: see if the modem is present in firmware download mode
* `--reboot`
* `--clear_attach_apn=<carrier_id>`: clear the attach APN in the modem NVM if
  the carrier ID is matching the one provided
* `--fw_version`: can be optionally passed along with `--flash_fw` to signify
  the firmware version(s) of the passed file(s), it using the same key/value
  syntax.

`--get_fw_info` should return a list of key/value one per line. The key is the
type of the firmware/version and the value is the actual version number
(not specific format defined). The separator between the key and the value is
a colon (`:`). The example below has the main firmware on the first line, the
carrier firmware version on the next line and the carrier UUIDn on the one after
that:

```
$ modem_program --get_fw_info
main:11.22.33.44
carrier:55.66
carrier_uuid:big-long-carrier-uuid-string
```

The carrier UUID should match with one from the shill mobile operator DB.

For `--flash_fw`, `--fw_version`, `--get_fw_info`, the following keys are
currently defined for the type:
* `main`: Main or base firmware (and its associated version).
* `carrier`: Carrier customization package (and its associated version).
* `oem`: OEM settings (and their associated version).
* `carrier_uuid`: the UUID of carrier for the current customization package.

`--flash_mode_check` should return the string "true" if the modem is present
in flash mode, and something else otherwise (preferably "false" for
readability).

All commands should return 0 on success and something non-zero on failure.
`modemfwd` will look for these binaries in the directory passed as the
`--helper_directory` argument on the command line.

## Helper and firmware directory structure

The protos defined in `helper_manifest.proto` and `firmware_manifest_v2.proto`
define manifests that should be provided in the helper and firmware directories
so modemfwd can figure out what devices, carriers, etc. the contents can be
used with.

[system API]: https://chromium.googlesource.com/chromiumos/platform/system_api/+/HEAD/switches/modemfwd_switches.h
