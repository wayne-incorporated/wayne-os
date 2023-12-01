# vm_tools - Utilities for Virtual Machine (VM) orchestration

This directory contains various tools for managing the lifetime of VM instances
and for providing any services those VMs may need while they are running.

[TOC]

## chunnel

`chunnel` tunnels traffic for servers that listen on `localhost`. This is a
common developer use case since `localhost` is allowed as a secure origin in
Chrome.

The `chunneld` binary runs on the Chrome OS host, and receives updates from
`vm_cicerone` notifying it of ports that should be listened to. When Chrome
connects to `localhost:port`, `chunneld` will accept the connection, open a
vsock listener, and launch the `chunnel` binary in the target container which
will connect back to `chunneld`.

## vm_concierge

[`vm_concierge`](concierge/README.md) is a system daemon that runs in Chrome OS
userspace and is responsible for managing the lifetime of all VMs.  It exposes a
[D-Bus
API](https://chromium.googlesource.com/chromiumos/platform/system_api/+/HEAD/dbus/vm_concierge/)
for starting and stopping VMs.

When `vm_concierge` receives a request to start a VM it allocates various
resources for that VM (IPv4 address, vsock context id, etc) from a shared pool
of resources.  It then launches a new instance of [crosvm] to actually run the
VM.

Once the VM has started up `vm_concierge` communicates with the `maitred`
instance inside the VM to finish setting it up.  This includes configuring the
network and mounting disk images.

## vm_cicerone

`vm_cicerone` is a system daemon that runs in Chrome OS userspace and is
responsible for all communication directly with the container in a VM. It
exposes a [D-Bus API](https://chromium.googlesource.com/chromiumos/platform/system_api/+/HEAD/dbus/vm_cicerone)
for doing things such as launching applications in containers, getting icons
from containers and other container related functionality as it is extended. It
also sends out signals for starting/stopping of containers.

`vm_concierge` communicates with `vm_cicerone` to keep the list of running VMs
in sync and also to retrieve status of containers and get security tokens.

When `vm_cicerone` communicates with a container, it is interacting with the
`garcon` component running inside of that container and is doing so over gRPC.

## maitred

`maitred` is the agent running inside the VM responsible for managing
the VM instance.  It acts as the init system, starting up system services,
mounting file systems, and launching the container with the actual application
that the user wants to run.  It is responsible for shutting down the VM once the
user's application exits or if requested to by `vm_concierge`.

See [docs/init.md](docs/init.md) for more details on the duties maitred carries
out as pid 1.

## garcon

`garcon` is a daemon that runs inside of a container within a VM. gRPC is used
to communicate between `vm_cicerone` and `garcon`. It is used to control/query
things inside the contaienr such as application launching, accessibility,
handling intents, opening files, etc. The communication is bi-directional. It
uses TCP/IP for the transport and firewall rules ensure that only the container
IPs are allowed to connect to the corresponding port for `garcon` that is open
in `vm_cicerone`.

## upgrade_container

`upgrade_container` is executed inside a container by Tremplin to upgrade the
container e.g. a Debian Stretch container to Debian Buster.

## p9

The [p9](p9/) directory holds a server implementation of the [9p] file system
protocol.  It is used by [crosvm] and the [9s](#9s) daemon to share files and
directories between the host and the VM.

## seneschal

`seneschal` is the steward of the user's /home directory. It manages processes
that serve the [9p] file system protocol. The 9p client lives in the guest
kernel and communicates with the server over [vsock].

Each server initially does not have access to any path but can be
granted access to specific paths in the user's home directory by sending
requests over dbus to `seneschal`. These paths are bind-mounted into
the server's root directory and become visible to the 9p clients of that
server.

This makes it possible to share different sets of paths with different
VMs by giving each of them access to a different 9p server.

## 9s

`9s` is program that serves the [9p] file system protocol.  `seneschal` launches
one instance of this program for each VM started by the user.  It is a small
wrapper around the [p9](#p9) rust library.

## vsh

`vsh` is a vsock-based remote shell utility. `vshd` runs on the guest/server,
and `vsh` runs on the host/client.

For more detailed docs, see [`vsh`](vsh/).

## vm_syslog

`vm_syslog` is the syslog daemon that runs inside the VM.  It is automatically
started by maitred and provides a socket at `/dev/log` for applications to send
it log records.  `vm_syslog` aggregates the log records and then forwards them
outside the VM to the logging service running on the host.  The logging service
tags the records it receives with the unique identifier for the VM from which
the logs originated and then either forwards them on to the host syslog service
or writes them to a file in the user cryptohome. This ensures that the VM logs
are captured in any feedback reports that are uploaded to Google's servers.

See [docs/logging.md](docs/logging.md) for more details on log handling.

## vm_pstore_dump

`vm_pstore_dump` is the command to print the console output of the guest
kernel.  It runs in Chrome OS userspace and reads the file which is on the host
file system and used as the backend of pstore of the guest kernel.  It is
intended to be used for collecting logs when the guest kernel fails to boot in
its early stage and other tools (e.g. logcat) are not available.

## crash_collector

`crash_collector` is responsible for collecting crash reports of applications
running inside the VM and forwarding them out to the crash collector service
running on the host system.  When `maitred` first starts up it configures
`/proc/sys/kernel/core_pattern` to start the `crash_collector` program and send
the core dump over a pipe to that program.  `crash_collector` then parses the
core dump and converts it to a minidump before sending it out to the host.
The host daemon passes the report on to `crash-reporter`, which takes care of
uploading it to Google servers.

## metric_collector

`metric_collector` is an IO reporting daemon for the default Crostini container.
It periodically polls the vmstats of the container (or really, the whole termina
VM, since the stats are not namespaced) and reports those to UMA by invoking
`garcon`.

## VM <-> host communication

All communication between `vm_concierge` and the applications inside the VM
happen over a [vsock] transport. The actual RPC communication uses the
[gRPC](http://grpc.io) framework. Every `maitred` instance listens on a known
port in the vsock namespace (port 8888).

See [docs/vsock.md](docs/vsock.md) for more details about [vsock].

### Authentication

Since each `maitred` instance listens on a known port number, it is possible for
an application inside a VM to send a message to `maitred` over a loopback
interface.  To prevent this we block all loopback connections over vsock.

It is not possible for processes in different VMs to send messages to each other
over vsock.  This is blocked by the host kernel driver that manages data
transfer.

### Wire format

gRPC uses [protocol buffers](https://developers.google.com/protocol-buffers) as
the serialization format for messages sent over the vsock and IP transport.  The
[proto](proto/) directory holds the definitions for all the messages sent and
services provided between the host and the VM/container.


[9p]: http://man.cat-v.org/plan_9/5/0intro
[crosvm]: https://chromium.googlesource.com/chromiumos/platform/crosvm
[vsock]: https://lwn.net/Articles/695981/
