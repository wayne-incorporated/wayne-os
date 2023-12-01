# screen-capture-utils

Utilities for screen capturing for dev/test images for working with screen
capture.

[TOC]

## screenshot

Provides a screenshot of the current display. Useful for capturing what's on the
display when test has failed, for example. Not all devices are supported yet, so
your mileage may vary.

## kmsvnc

VNC server using the same infrastructure as screenshot for grabbing display.

Here’s a quick rundown of how to use kmsvnc.

![kmsvnc usage diagram](kmsvnc-usage.png)

```shell
(DUT)# kmsvnc
```

VNC server will start listening on port 5900.

### Using a VNC viewer.

Forward the port 5900 with SSH from your client, and connect through the port.
Example:

```shell
(workstation)$ ssh -L 5900:localhost:5900 DUT  # Keep this running to forward port.
```

Then connect using a VNC client. It could be any client but tigervnc-viewer
Debian package worked well from crostini on fizz. Make the client connect to
`localhost` port 5900 (which is display number 0, the parameter for
xtigervncviewer becomes `localhost:0`)

```shell
(workstation)$ sudo apt install tigervnc-viewer  # to install on Debian.
(workstation)$ xtigervncviewer localhost:0
```

### Using novnc.

novnc is a VNC client on the web. On test images novnc is available. It will
start listening to port 6080, open browser to point to the page.

```
(workstation)$ ssh -L 6080:localhost:6080 DUT
(DUT)# kmsvnc &
(DUT)# novnc &
Navigate to this URL:

    http://localhost:6080/vnc.html?host=localhost&port=6080

Press Ctrl-C to exit

```

If you're in a local network such as a home network, this might be an option to
open the port directly so you can connect directly, specifying the DUT IP
address directly like: `http://${DUT}:6080/vnc.html?host=${DUT}&port=6080`

```
(DUT)# iptables -I INPUT -p tcp --dport 6080 -j ACCEPT
```

### Reporting bugs

TODO(uekawa): set up component for crbug.

For Googlers please use http://go/kmsvnc-bug to file a bug. Current known issues
are available at http://b/hotlistid:2869886

## Development notes

### Building and testing

For development I typically deploy to /usr/local/ because tests expect them
there.

```
$ BOARD=rammus
$ DUT=localhost:2229
$ setup_board --board=${BOARD}  # required only once per board.
$ cros_workon --board=${BOARD} start screen-capture-utils
$ emerge-${BOARD} -j 100 chromeos-base/screen-capture-utils
$ cros deploy --root=/usr/local/ "${DUT}" chromeos-base/screen-capture-utils
$ tast run "${DUT}" graphics.KmsvncConnect
$ tast run "${DUT}" graphics.Smoke.platform
```

For debugging I typically need to deploy to /usr/sbin, from inside chroot

```
$ cros deploy "${DUT}" chromeos-base/screen-capture-utils
$ gdb-${BOARD} --remote="${DUT}" /usr/sbin/kmsvnc
```

To run unit-tests

```
$ FEATURES=test emerge-$BOARD screen-capture-utils
```

### Running with more logs

With extra verbosity kmsvnc outputs things like fps logs. Use vmodule flag to
enable such extra logging.

```
kmsvnc --vmodule=kmsvnc=2
```
