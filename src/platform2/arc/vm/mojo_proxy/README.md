# ARCVM mojo proxy

ARCVM mojo proxy proxies data sent over file descriptors used for mojo
communication between the host and the guest.

```
        Chrome
           |
     Host mojo proxy
           |
        crosvm
           |
 +---------+----------+
 |ARCVM    |          |
 |         |          |
 |    Guest kernel    |
 |         |          |
 |  Guest mojo proxy  |
 |         |          |
 | ARC bridge service |
 |                    |
 +--------------------+
```

## virtio-wl connection initialization

1.  In the guest VM, the guest mojo proxy process creates a named virtio-wl
    context whose name is "mojo".
1.  The guest kernel sends this request to crosvm's virtio-wl process in the
    host.
1.  In the host, crosvm's virtio-wl process forwards this request to a named
    UNIX domain socket `/run/arcvm/mojo/mojo-proxy.sock`.
1.  The host mojo proxy process listens on `/run/arcvm/mojo/mojo-proxy.sock` and
    accepts the connection.
1.  Now the guest mojo proxy process and the host mojo proxy process are
    connected by virtio-wl. Data sent to the virtio-wl context in the guest can
    be received by `/run/arcvm/mojo-proxy.sock` in the host and vice versa.

## Mojo channel initialization

1.  In the guest VM, the ARC bridge service connects to a named UNIX domain
    socket `/var/run/chrome/arc_bridge.sock`.
1.  The guest mojo proxy process listens on `/var/run/chrome/arc_bridge.sock`
    and accepts the connection.
1.  The guest mojo proxy process sends the host mojo proxy process a connection
    request.
1.  In the host, the host mojo proxy process handles the connection request by
    connecting to a named UNIX domain socket `/run/chrome/arc/arc_bridge.sock`.
1.  The chrome browser process listens on `/run/chrome/arc/arc_bridge.sock` and
    accepts the connection.
1.  Now the ARC bridge service in the guest VM and the chrome browser process in
    the host are connected by a proxied UNIX domain socket via mojo proxy
    processes.
