# Developer notes

The scope of this document is to provide useful commands to work as
a developer of hiberman.

## Hiberman utility

Hiberman application has multiple subcommands that allow you to initiate
suspend/resume or verify hibernation status.

```
# hiberman --help
Usage: hiberman subcommand [options]
This application coordinates suspend-to-disk activities. Try
hiberman <subcommand> --help for details on specific subcommands.

Valid subcommands are:
    help -- Print this help text.
    hibernate -- Suspend the machine to disk now.
    resume-init -- Perform early initialization for resume.
    resume -- Resume the system now.
    abort-resume -- Send an abort request to an in-progress resume.
    cat -- Write a disk file contents to stdout.
    cookie -- Read or write the hibernate cookie.
```

### Run on a local DUT

Hiberman utility allows initiating an end-to-end test.
The device will enter the shutdown mode. To initiate the resume, the user
has to press the Power button or use Servo/SuzyQ cable.

### Dry-run on a local DUT

Hiberman utility allows initiating an end-to-end test using dry-run mode.
The main difference from a standard hibernate end-to-end process, is that
dry-run flag won't request to enter the final step (which is device shutdown).

### Reviewing the logs

Logs come out in the syslog using:
```
tail -f /var/log/messages | grep -ai hiber &`
```
Interaction with the serial console works better with hibernate, since SSH
tends to drop and block terminal when the machine is powering down.

In the resume boot, execute:
```
dmsetup table
```
to see if the snapshot targets are mounted, indicating writes to stateful
are currently being diverted.
