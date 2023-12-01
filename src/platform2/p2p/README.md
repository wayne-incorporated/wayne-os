# p2p: Service for sharing files between Chrome OS devices

[TOC]

## About

`p2p` is a software package for advertising and discovering content on the
local network (LAN). It is built on top of HTTP and mDNS/DNS-SD. `p2p` is
written specifically for Chrome OS and uses services and conventions specific
to that OS. It is not intended to be portable to other OSes.

## Files

Content to be shared with other devices on the LAN is to stored in an encrypted
part of the stateful partition. The following directory is used:

    /var/cache/p2p

In the following this directory shall be referred to as `$(P2P_DIR)`.

## Theory of Operation

Files to be shared are advertised via a DNS-SD service with the service type
`_cros_p2p._tcp`.

The address and port number advertised in the DNS-SD service refer to a HTTP
server running on the same machine. To simplify firewall management, port 16725
("AU") is always used but in the future this may by dynamic.

Any file with a `.p2p` file extension in `$(P2P_DIR)` is advertised as a TXT
record in a DNS-SD response where its value is the length of the file (decimal
encoding). For example, if the file `$(P2P_DIR)/some_payload.bin.p2p` exists
and is 123456789 bytes long, the DNS-SD response will advertise a TXT record
`id_some_payload.bin=123456789` (the `id_` prefix is there just for namespacing
purposes). By convention, this allows any client to download the file using the
URL

    http://<IP>:<PORT>/some_payload.bin

where `IP` and `PORT` is taken from the DNS-SD response. Additionally, to allow
sharing files that are not completely downloaded yet, one can set the
`user.cros-p2p-filesize` extended attribute with the final size. This will make
the HTTP server block until content is available. Note that the mDNS/DNS-SD
response always returns the size of the file on disk - this is to allow a peer
to pick the peer with e.g. the most downloaded bytes.

Note that the size set in the `user.cros-p2p-filesize` extended attribute - if
present - is always constant (because it contains the final size of the file).
In contrast, the size conveyed via the mDNS/DNS-SD response reflects the actual
size of the file which grows as more and more data is being downloaded. As
such, this value is not necessarily constant and in fact, by virtue of how
mDNS/DNS-SD works, changes to the value are propagated on the local network. To
conserve bandwidth with frequently changing files, file size changes are
propagated at most every ten seconds.

The `$(P2P_DIR)` directory is the sole interface for other software on the
local system to share files with other peers. For example, if the
`update_engine` program (used for updating Chrome OS) is downloading an payload
it can create a file, say `$(P2P_DIR)/some_update_xyz.bin.p2p.tmp` and start
writing to it as it downloads the rest of the payload. When the `update_engine`
program has verified that the file is authentic (by e.g. checking a
cryptographic signature in the beginning of the file) and it knows the final
size, it can

-   sets the `user.cros-p2p-filesize` xattr to the size
-   rename the .tmp extension away
-   proceed to write payload to the file

and, hey presto, the file some_`update_xyz.bin` is now shared with the rest of
the local network.

In addition to advertising files, the `_cros_p2p._tcp` DNS-SD service will also
advertise the current number of HTTP connections in the num-connections TXT
attribute. This can used (in a cooperative manner) to limit the number of
simultaneous downloads in the LAN.

## Programs

The `p2p` package is comprised of three programs.

### `p2p-server`

The primary purpose of this program is to monitor the `$(P2P_DIR)` directory
and advertise `.p2p` files via mDNS/DNS-SD (it uses the Avahi package to do
this). When there is a non-zero number of .p2p files, it will start the
`p2p-http-server` program and when the number of `.p2p` files drop to zero it
will terminate kill the instance.

This program is run as a daemon (long-running process) and is usually started
via an Upstart job, `p2p`, to ensure the firewall is properly configured
(specifically, opening the TCP port that the HTTP server will listen on), its
dependencies (e.g. Avahi) has started and that the program is launched with
appropriate privileges (using minijail0 to drop privileges).

### `p2p-http-server`

The purpose of this program is to serve `.p2p` files via HTTP. It is started
and stopped by the `p2p-server` server, when needed.

### `p2p-client`

This is a simple program to discover content available on the LAN. Given a file
identifier, it looks on the LAN for `_cros_p2p._tcp` DNS-SD services. If one or
more peers have the file, `p2p-client` picks one of them and prints the URL on
stdout.

## Users and Permissions

### `p2p` User and Group

The `p2p` user (and `p2p` group) is used to run `p2p-server` and
`p2p-http-server` without root privileges.

### Permissions on `$(P2P_DIR)`

The `$(P2P_DIR)` is owned by root and its permissions are `rwxr-xr-x`, that is

-   any (non-jailed) user on the system can read files in `$(P2P_DIR)`
-   only root can write files

In the future a more sophisticated ACL scheme may be introduced to allow known
unprivileged programs (say, `update_engine`) to share content.

## Frequently Asked Questions

(TODO: write me)
