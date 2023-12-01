# Chrome OS MEMS Setup Code

## `/usr/sbin/mems_setup`

This tool handles the boot-time setup of cros_ec sensors on the device, such as
accelerometers, gyroscopes, and potentially other sensors in the future.

The goals of introducing this tool vs. using a shell script include:
 - improved testability;
 - more readable;
 - better performance.

This tool is based on `libmems`.

## Configuration

Currently, the actions taken by the tool are statically determined by
the type of sensor being initialized, and the only values that are discovered
at runtime are the VPD calibrations. If your use case needs tweaking the
behavior of this tool in other ways, please file a bug.
