# Chrome OS Flex Bluetooth

`process_flex_bluetooth_overrides` is an executable that runs before Floss
starts (see the `Upstart` job configuration file at `init/flex-bluetooth.conf`)
and applies overrides for Floss on Flex. It looks at the Bluetooth adapters on
the system and writes the overrides found (for the Bluetooth adapter) to the
file `/var/lib/bluetooth/sysprops.conf.d/floss_reven_overrides.conf`, which is
read by Floss.
