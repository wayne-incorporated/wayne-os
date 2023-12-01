# g2ftool : U2F command line interface tool

g2ftool is a command line tool to interact with U2FHID devices, whether
physical devices or the virtual one provided by u2fd.

## Usage

The tool can send basic commands such as `ping`, raw messages, as well as
more complex commands such as register and authenticate.

For all commands, a device must be specified, this will typically be
something like `/dev/hidraw3`.

### Basic Command Examples

To send a U2F_PING command:

```
g2ftool --dev=/dev/hidraw<n> --ping
```

You may like to increase verbosity to see details of the messages sent:

```
g2ftool --dev=/dev/hidraw<n> --v=3 --ping
```

### Register

Sends a U2F_REGISTER message.

```
g2ftool --dev=/dev/hidraw<n> --reg --application=<sha256(app)>
                                   --challenge=<sha256(challenge)>
```

Output will include a key_handle for this new registration.

### Authenticate

Sends a U2F_AUTHENTICATE message.

```
g2ftool --dev=/dev/hidraw<n> --auth
                             --application=<value provided at registration>
                             --challenge=<value provided at registration>
                             --key_handle<value returned after registration>
```
