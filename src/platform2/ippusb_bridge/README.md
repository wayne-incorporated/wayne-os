# Ippusb Bridge

`ippusb_bridge` manages communication with a printer that supports the
[USB IPP protocol][IPP-over-USB].  After being started by `udev` when a
supported device is plugged in, `ippusb_bridge` proxies HTTP requests to the
printer's web server through its IPP-over-USB endpoints.  This allows driverless
network protocols such as eSCL and IPP to be used over USB.  `ippusb_bridge`
listens on a local socket under `/run/ippusb` by default, but can also be
configured to listen on a local TCP port.

`ippusb_bridge` was originally a drop-in replacement for [`ippusbxd`][ippusbxd]
for Chrome OS.  Similar to [`ipp-usb`][ipp-usb], `ippusb_bridge` adds full
understanding of HTTP requests so that it doesn't leave the IPP-over-USB tunnel
in an invalid state if a client doesn't fully process a request or response.
We would originally have preferred to use `ipp-usb` on Chrome OS instead, but
its binary size (~9MB) precludes it.

Since then, `ippusb_bridge` has also taken over the functionality of
`ippusb_manager` (which no longer exists) and has gained other Chrome OS
specific features (local sockets, sharing USB interfaces with `cupsd`, etc).

*** aside
Googlers: see http://go/cros-image-size-process-proposal for context on why
9 MB is considered "too big" for inclusion.
***

## Invocation

*   `ippusb_bridge` registers [udev rules][udev-rules] that spawn it when
    `udevd` detects a newly-attached USB printer that supports IPP-over-USB
    interfaces.
*   The udev trigger launches an [upstart job][upstart-bridge-start]
    for process lifecycle management.
*   Because it processes untrusted data (print jobs and other HTTP exchanges),
    `ippusb_bridge` runs in a `minijail`ed environment with
    [seccomp filters][seccomp-filters].

## General Operation

*   The primary goal of `ippusb_bridge` is to maintain a Unix socket in a
    predictable location, facilitating communication from either
    [`cupsd`][cupsd-ippusb-patch], [`lorgnette`][lorgnette], or other
    local software that has appropriate permissions.
    *   This particular functionality is unique to the copy of CUPS packaged for
        Chromium OS.
    *   The socket's containing directory is `/run/ippusb` and its basename is
        built from its vendor ID and product ID: `${VID}-${PID}.sock`.
        These IDs propagate from the udev trigger down to a [command-line
        argument][unix-socket-argument] given to `ippusb_bridge`.
*   `ippusb_bridge` continues running, ferrying messages back and forth across
    the given Unix socket, until the printer is unplugged.
*   When no clients are actively using an IPP-over-USB interface,
    `ippusb_bridge` releases the interfaces after a timeout.  This allows
    traditional `cupsd` communication to the same device through the standard
    printer USB classes.  `ippusb_bridge` automatically reclaims interfaces when
    a new client connects.

## Debugging

### Upstart
Upstart will try to keep `ippusb_bridge` running as long as the USB device is
plugged in.  If you need to run it by hand, you can stop the upstart job first:

```
stop ippusb-bridge BUS=NNN DEV=MMM VID=xxxx PID=yyyy
```

_NNN_ and _MMM_ need to be 3 characters.  _xxxx_ and _yyyy_ need to be 4
lowercase hex characters.

If you run it by hand without the `-s` argument, `ippusb_bridge` will listen on
`localhost:60000` instead of a socket in `/run/ippusb`.  This can be handy if
you have want to compare the behavior with `ipp-usb` or some other software that
doesn't support local sockets.  Since `ippusb_bridge` doesn't advertise on mDNS,
you will need to manually construct a scanner URL, such as
`airscan:escl:Test:http://localhost:60000/eSCL/`.

Note that running by hand may produce different behavior due to the lack of
sandboxing.  If you need to reproduce the sandboxed environment, you can replace
`stop` with `start` in the above command to get upstart to launch
`ippusb_bridge` again.

### Signals

`ippusb_bridge` expects to be stopped with `SIGINT`, not `SIGTERM`.  If you kill
it by hand, be sure to use `kill -INT`.  Otherwise, `ippusb_bridge` will leave
its socket behind in `/run/ippusb` and will not start again until the socket is
removed manually.

### Protocol traces

If you run `ippusb_bridge` with the `-v` flag, it will dump most HTTP traffic to
the log.  You can add this flag to the upstart job and stop/start as described
above, or run `ippusb_bridge` by hand.  Note that the traffic will not be
decoded.

`cupsd` and `sane-airscan` also have their own mechanisms for dumping
higher-level protocol info, or see below for a way to get the lower-level USB
traffic if needed.

### USB

If the USB tunnel gets into a funny state, restarting `ippusb_bridge` will often
clean it up when it resets the device's active configuration.  It is not
uncommon to trigger USB problems during development, but if you find a
reproducible way to leave the tunnel in a non-functioning state during normal
operation, please file a bug.

When things are going wrong with low-level communication, it can be helpful to
sniff the raw USB packets:

1.  `modprobe usbmon`
1.  `lsusb` and find the bus where the printer is attached
1.  `tcpdump -i usbmonN -w /tmp/usbmon.pcap`, where _N_ is the bus number
1.  Copy `/tmp/usbmon.pcap` to your workstation and open it in wireshark.  You
    may need to enable some additional USB protocols under _Analyze -> Enabled
    Protocols_

## Miscellanea

*   `ippusb_bridge` depends on [the `tiny_http` crate][tiny_http]. `tiny_http`
    was patched
    *   to build without SSL features and
    *   to support operating over Unix sockets.

[IPP-over-USB]: https://www.usb.org/document-library/ipp-protocol-10
[ippusbxd]: https://www.github.com/OpenPrinting/ippusbxd
[ipp-usb]: https://github.com/OpenPrinting/ipp-usb
[tiny_http]: https://source.chromium.org/search?q=lang:ebuild+file:tiny_http&ss=chromiumos
[udev-rules]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/HEAD:src/platform2/ippusb_bridge/udev/99-ippusb.rules
[upstart-bridge-start]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/HEAD:src/platform2/ippusb_bridge/init/ippusb-bridge.conf
[seccomp-filters]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/HEAD:src/platform2/ippusb_bridge/seccomp/
[cupsd-ippusb-patch]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/HEAD:src/third_party/cups/backend/ipp.c;l=663;drc=277c6fad6c409edb86d4458338b991167c1e87d0
[lorgnette]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/HEAD:src/platform2/lorgnette/
[unix-socket-argument]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/HEAD:src/platform2/ippusb_bridge/src/arguments.rs;l=41;drc=3ac71c91bf3311868c4cc97dbd8f2983332667ac
