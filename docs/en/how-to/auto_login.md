# Note
This document is in progress.
<br>This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).
<br>The features in this document have not been released yet. (2022-03-17)

## Requirement
- Server: A Wayne OS PC that runs _test_ version
- Client: A PC with ssh client feature (any OS is fine, but this document will explain with Linux shell)
- Check an IP address of the server and make sure the IP is reachable from the client (ex: `ping ${SERVER_IP}`)

## 1. Preparation
#### SSH
Setup and check [ssh connection](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/ssh_connection_from_remote.md).
#### Google ID
Temporary Google ID is recommended since this auto login feature is not secure, and it's convenient to use auto login, if you turn off 2-Step Verification for the Google ID.
#### GCP
#### Server
Turn on _Wayne OS test version_ and setup initial configuration (language/network/etc).

## 2. Remote login
#### Connect ssh from client to server.
~~~
$ sudo ssh ${SERVER_IP} "/usr/local/autotest/bin/autologin.py -u '${USER_ID}'"
Password:

...

Warning: Password input may be echoed.
Password:
~~~
- ${SERVER_IP}: The IP address of Wayne OS device (ex:192.168.0.100)
- ${USER_ID}: Google ID for login
- 1st Password prompt: _Wayne OS test_ version's shell password
- 2st Password prompt: Password for the Google ID 
#### Options with example
~~~
$ sudo ssh 192.168.0.100 "/usr/local/autotest/bin/autologin.py --help"
Password:

...

usage: autologin.py [-h] [-a] [--arc_timeout ARC_TIMEOUT] [-d] [-u USERNAME]
                    [--enable_default_apps] [-p PASSWORD] [-w]
                    [--no-arc-syncs] [--toggle_ndk] [--nativebridge64]
                    [-f FEATURE] [--url URL]

Make Chrome automatically log in.

optional arguments:
  -h, --help            show this help message and exit
  -a, --arc             Enable ARC and wait for it to start.
  --arc_timeout ARC_TIMEOUT
                        Enable ARC and wait for it to start.
  -d, --dont_override_profile
                        Keep files from previous sessions.
  -u USERNAME, --username USERNAME
                        Log in as provided username.
  --enable_default_apps
                        Enable default applications.
  -p PASSWORD, --password PASSWORD
                        Log in with provided password.
  -w, --no-startup-window
                        Prevent startup window from opening (no doodle).
  --no-arc-syncs        Prevent ARC sync behavior as much as possible.
  --toggle_ndk          Toggle the translation from houdini to ndk
  --nativebridge64      Enables the experiment for 64-bit native bridges
  -f FEATURE, --feature FEATURE
                        Enables the specified Chrome feature flag
  --url URL             Navigate to URL.

$ sudo ssh 192.168.140.172 "/usr/local/autotest/bin/autologin.py --url 'https://wayne-os.com' -u 'seongbin@wayne-inc.com' -p 'my_private_pw'"
~~~


## Reference
https://chromium.googlesource.com/chromiumos/docs/+/main/tips-and-tricks.md#how-to-enable-a-local-user-account 
