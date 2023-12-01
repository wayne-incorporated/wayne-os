# Design doc: debugd

## Objective

Expose system debugging information over DBus to allow better sandboxing
of the user session and more detailed diagnostic availability through
Chrome.

## Background

Currently, our debugging and diagnostic tools (specifically those
implemented in `crosh` and in `chrome://system`) work by shelling out
to run binary code. This exposes a lot of surface area via crosh (and
Chrome, to a lesser extent) and forces us to allow those contexts to
execute programs and read files, which they otherwise have no need to
do. Another concern is that some of these diagnostics (for example,
crosh's 'ping') command rely on executing setuid binaries. Removing
the ability to use setuid altogether from the user session and from
crosh removes a lot of attack surface that is otherwise exposed in the
linker and kernel.

## Overview

Safely expose system debugging information over DBus. This allows us to
restrict contexts which otherwise must have very broad access to exec()
and setuid binaries to communicating over DBus.

## Detailed Design

The debug daemon will be implemented as a single daemon, running as an
unprivileged user, communicating over DBus. It will accept commands over DBus
and either compute the information itself or run a helper program, then hand the
result back over DBus. The debug daemon does not cache results for repeated
requests. The debug daemon will run under strict seccomp system-call
filtering rules, which will reduce the kernel ABI exposed to debugd and
its helpers.

The debug daemon will present its functionality as a single object at a
fixed path `/org/chromium/debugd` implementing the interface described
in [`/dbus_bindings/org.chromium.debugd.xml`][iface]. All the debugd
methods can be synchronous, since it is used only to fetch debugging info - we
don't need to worry about concurrent users since it is unlikely that the user
will run two debug commands from two different crosh instances at once,
and even if they do, the commands will be queued. Making `chrome://system`
slower is something we do need to be concerned about. An example method
might be:

    CellularStatus : () -> a{sv}

"CellularStatus takes nothing and returns a map from string to variant."

The implementation is documented in [`/doc/implementation`][impl]. In general,
the debug daemon blocks inside DBus, waiting for incoming messages; when
it receives a message, it looks up the incoming message name in a method
table and calls the associated function. The function gathers
information and replies to the DBus message as needed.

The debug daemon also has a list of helpers, fixed at compiletime; when
debugd starts up, it creates a new tmpfs, visible only to it and its
descendants, and mounts it at `/mnt/debugd`. Each of the helper programs
is then launched, and can spool information into the tmpfs as desired,
presumably for collection by some method inside debugd. Some helpers are
launched as needed instead of running persistently. Helper sources live
in [`/src/helpers`](../src/helpers/).

Files stored in the tmpfs can be written as json. Doing so makes it
easier to write helpers, since a utility function is available for
"reply to this dbus message with this json structure". Protocol buffers
are unsuitable for this because they are not self-describing; we would
need to compile separate protobuf deserializers for each method into
debugd and choose which one to use for each file.

## Returning Complex Datastructures

Some methods have to return data structures that are not simple (for
example, the 'GetModemStatus' method). For these methods, we have three
choices for moving the complex data structure across DBus:

1.  Transport them in DBus' wire format directly.
    * P: No conversions needed in debugd
    * P: Everyone talking to us implicitly speaks it
    * C: Chrome needs to turn DBus wire format into its internal Value type
         for use/display
2.  Transport them as protocol buffers.
    * P: Typesafe on the wire
    * C: Need to convert DBus to protobuf in debugd
    * C: Need a C/C++ helper for crosh to print these
    * C: Chrome needs to turn these into its internal Value type
3.  Transport them as JSON.
    * P: Chrome can serialize/deserialize directly.
    * P: Human-readable; can be shown directly to user by crosh
    * P: Parseable from Javascript; can manipulate it from an
         extension.
    * C: Typesafe only at endpoints
    * C: Need to convert DBus to JSON in debugd

We use JSON; although it makes more work for debugd, it makes it easier for
Chrome and crosh to use debugd.

## Security Considerations

This daemon will have its own attack surface which we need to take care
of. Argument sanitization is of paramount importance, although using
execve() instead of /bin/sh to run commands will remove an entire class
of attacks that crosh currently has.

There are some security mitigations we can apply to debugd itself:

1.  We can drop to a different uid/gid.
    *   If we use a dedicated gid for debugd, we can take a lot of
        files that are currently world-readable and instead make them
        root:debugd 0640.
2.  We can chroot and put ourselves in a bare vfs namespace.
    *   If we do this, we have to bring the things we need into our
        namespace with us, although we can make their mounts
        read-only.
    *   This doesn't really buy us anything over seccomp-filter if
        our policy is appropriately tight, but eventually we might
        need to allow writes for some debug tools, which would make
        this a good line of defense.
3.  We can seccomp-sandbox ourselves with syscall filtering, since we
    should only need to do a fairly restrictive set of things.
    *   This will probably involve a lot of effort. Tracking down
        which syscalls various helper programs use and keeping the
        filter policy up-to-date will take time.
    *   The decrease in kernel and platform (filesystem permissions,
        etc.) attack surface gained is worth it.
4.  We can set rlimits, if we feel so inclined.
    *   The particular gain we might get here is that we can restrict
        the number of outstanding helper programs we can have running
        at a time, which might avoid systemwide denial-of-service
        attacks.
    *   On the other hand, it opens us up to much easier denial of
        service against the debug daemon. The debug daemon would have
        to kill helper programs that ran past a certain time limit,
        but perhaps it has to do this already.

There are some mitigations we can't apply yet:
1.  We can't enable SECURE_NOROOT, since some of our helper programs
    (e.g. /bin/ping) are setuid. Fixing this is going to require some
    fairly major legwork.
2.  We can't use a pid namespace, because this destroys the crash
    reporter on 2.6.38. There's a patch floating around to fix this that
    we'd need to apply.
3.  We can't use a network namespace, because some of our tools (ping,
    traceroute) need access to the real network.

## Testing Plan

We can broadly divide debugd's functionality into two classes for
testing purposes: functions that generate new information (like ping or
traceroute), and functions that return already-generated information
(like reading information out of sysfs).

Functions that generate new information are often sensitive to the
surrounding hardware/network environment - for example, pinging an
outside host relies on working networking and such. We can sometimes
test these functions by relying only on things we know exist in any reasonable
test environment (like pinging 127.0.0.1 and making sure we get
properly-formatted output), but some of them (3g status, for example)
rely on hardware state, and for these we need a human to ensure the
output lines up with hardware.

Functions that return already-generated information can be tested by
using minijail's chroot-and-bind functionality to fake the
already-generated information, then testing debugd's returns against the
known fake data.

ellyjones: add more detail here

[iface]: ../dbus_bindings/org.chromium.debugd.xml
[impl]: implementation.md
