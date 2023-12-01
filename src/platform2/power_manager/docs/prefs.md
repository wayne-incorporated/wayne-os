# Prefs

Prefs is a key-value store, providing read (and some write) access to
configuration values. Prefs are [widely used] in powerd.

Prefs are read from the following sources:

- powerd's own local store,
- the embedded controller,
- cros_config,
- board specific read-only prefs, and
- the default read-only prefs.

These are scanned in order, first the read/write store, then cros_config, the
embedded controller and finally the read-only store. Pref values may also be
written to the read/write store, where they will override pref values from the
cros_config and embedded controller. The sources are defined in the
`GetDefaultSources()` function of [prefs.cc].

[prefs.cc]: ../common/prefs.cc
[chromeos-config]: ../../chromeos-config

## Pref Keys and Values

Pref keys are strings, defined in [common/power_constants.cc]. An example is
"`battery_poll_interval_ms`".

Pref values are also stored as strings, and a range of convenience methods on
the [Prefs Interface] allows them to also be read and written as `bool`,
`double`, `string` and`int64`.

[widely used]: https://source.chromium.org/search?q=file:powerd%20%2Fprefs.h&ss=chromiumos%2Fchromiumos%2Fcodesearch:src%2F
[common/power_constants.cc]: ../common/power_constants.cc
[prefs interface]: ../common/prefs.h

## Pref Sources

### The Read/Write Store aka FilePrefsStore

The highest priority source is the read/write [FilePrefsStore]. As well as being
a source, it is a 'Store' since values can also written to it. The store is
empty by default, and only contains values after they are written. Local store
values are kept in files in the directory `/var/lib/power_manager`. Each file
is named with the pref key, and the content of the file is the stored string
value.

Note that there are only a few cases where powerd [stores pref values].

When testing or debugging it is common to override prefs from other sources
by placing files and values into `/var/lib/power_manager`. See [Overriding Pref Values](#overriding-pref-values), below.

[fileprefsstore]: ../common/file_prefs_store.h
[`/var/lib/power_manager`]: ../power_manager/common/prefs.cc
[stores pref values]: https://source.chromium.org/search?q=file:powerd%20%2Fprefs.h%20Set(String%7CInt%7CBool%7CDouble)&sq=&ss=chromiumos%2Fchromiumos%2Fcodesearch:src%2F

### The Embedded Controller aka CrosEcPrefsSource

The [CrosEcPrefsSource] sources values from the embedded controller. Only two
keys are served by the EC:

- `low_battery_shutdown_percent` and
- `power_supply_full_factor`.

It is convenient to read these values via the prefs mechanism because they can
be overridden as needed via [FilePrefsStore]  and the `/var/lib/power_manager`
directory.

[crosecprefssource]: ../common/cros_ec_prefs_source.h

### cros_config aka CrosConfigPrefsSource

The [CrosConfigPrefsSource] reads values from the standard ChromeOS
configuration system, [chromeos-config]. Most prefs come from this source.

[chromeos-config/README.md] lists the keys stored in chromeos-config and used by
power_manager. This list of keys is taken from [common/power_constants.cc] by
[power_manager_prefs_gen_schema.py] which generates the [YAML schema] used by
chromeos-config for power prefs.

[boxster config] is used in addition to YAML for populating chromeos-config. It
is not clear to this documents' author what the relationship is between the
YAML-based and boxster systems.

[CrosConfigPrefsSource]: ../common/cros_config_prefs_source.h
[chromeos-config/readme.md]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/chromeos-config#power
[power_manager_prefs_gen_schema.py]: ../..//chromeos-config/cros_config_host/power_manager_prefs_gen_schema.py
[yaml schema]: ../../chromeos-config/cros_config_host/power_manager_prefs_schema.yaml
[boxster config]: http://go/boxster-ng

### Read Only File Sources

There are two more file-based prefs sources, which read prefs from
`/usr/share/power_manager/board_specific` and `/usr/share/power_manager`. They
use the same [FilePrefsStore] class as the read/write store, but no values are
ever written.

The values for the `/usr/share/power_manager` directory are taken from the
contents of the [default_prefs] directory. They are overridden by the
`board_specific` prefs which are installed by board support packages
([example]).

[default_prefs]: ../default_prefs
[example]: http://crsrc.org/o/src/overlays/overlay-brya/chromeos-base/chromeos-bsp-brya/chromeos-bsp-brya-0.0.2-r143.ebuild;l=83;drc=4192190dac699b94821f1942467706896ab389c6

## Overriding Pref Values

For testing and debugging, it an be useful to override pref values. This can be
done by writing files onto the read-write partition at `/var/lib/power_manager`.
The values written here will [override values from other sources](
#the-readwrite-store-aka-fileprefsstore), including [chromeos-config]. For most
pref keys, powerd will need to be restarted in order to pick up the new values.

To revert to the normal behavior, remove the files that you just created from
`/var/lib/power_manager` and restart powerd.

To temporarily change prefs in an autotest, use [PowerPrefChanger].

[PowerPrefChanger]: https://chromium.googlesource.com/chromiumos/third_party/autotest/+/HEAD/client/cros/power/power_utils.py
