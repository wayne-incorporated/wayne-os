# Device Policy Utilities
A cmd-line tool and related library to set or override device policies
on the device.

## Library libmgmt
Provides a simple API to set device policies on the device. Local policies are
written as JSON files to `/etc/opt/chrome/policies/recommended`. Chrome
automatically reads these files and, if properly formatted, use them as local
policy setting. For instance, calling
`PolicyWriter::SetDeviceAllowBluetooth(true)` writes the JSON string

`{ "DeviceAllowBluetooth": true }`

to `/etc/opt/chrome/policies/recommended/device_allow_bluetooth.json`, thus
allowing the user to enable bluetooth.

## Tool policy
A convenience cmd-line to tool to set and clear local device policies.

### Examples
`policy set DeviceAllowBluetooth true` set the policy DeviceAllowBluetooth to
true using the methodology explained under "Library libmgmt" above.

`policy clear DeviceAllowBluetooth` reset policy DeviceAllowBluetooth to
the default or to whatever it is set to in the Chrome OS Admin panel.

Type `policy --help` for detailed help and `policy --list` for a list of
policies this tool can edit.
