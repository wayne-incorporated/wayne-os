# bootid-logger - Record the current boot id to log.

This is intended to be used by [croslog](../croslog/).

Design doc: go/cros-journald-removal


# Format of the boot ID log

The boot IDs are stored in /var/log/boot_id.log. Each line corresponds to a single boot.

The example of line (in this case, the boot ID is "12345678901234567890123456789012")
> 2020-12-01T00:00:00.000000+00:00 INFO boot_id: 12345678901234567890123456789012
