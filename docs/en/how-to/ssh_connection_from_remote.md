## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).

## Requirement
- Server: A Wayne OS PC that runs _dev_ or _test_ version
- Client: A PC with ssh client feature (any OS is fine, but this document will explain with Linux shell)
- Check an IP address of the server and make sure the IP is reachable from the client (ex: `ping ${SERVER_IP}`)

## Wayne OS dev version
#### Connect to server from client
ID: chronos
<br>PW: _wayne-os-dev_ version's password
- For example:
~~~
$ ssh chronos@192.168.140.172
Password:
~~~
#### Ommiting PW 
TODO: write

## Wayne OS test version
#### 1. Setup on client
First, download the testing RSA keys and configuration files into ~/.ssh/
~~~
$ cd ~/.ssh && wget \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/testing_rsa \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/testing_rsa.pub \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/config
~~~
Then restrict the permissions on ~/.ssh/testing_rsa
~~~
$ chmod 0600 ~/.ssh/testing_rsa
~~~
And replace _000.000.000.000_ to IP address of the client, in _config_ file by editor.
~~~
$ vim ~/.ssh/config
~~~
~~~
# Example
Host wayne-os
  CheckHostIP no
  StrictHostKeyChecking no
  IdentityFile %d/.ssh/testing_rsa
  Protocol 2
  User root
  HostName 000.000.000.000  # Replace here to server IP
~~~
#### 2. Connect to server from client
~~~
$ ssh wayne-os
~~~
Then you will get a root-shell without password.
<br>If connect to multiple servers, you can share common config options in your ~/.ssh/config.
~~~
# Example
Host 172.22.168.*   # The subnet containing your Servers
  CheckHostIP no
  StrictHostKeyChecking no
  IdentityFile %d/.ssh/testing_rsa
  Protocol 2
  User root

Host wayne-os1
  HostName 172.22.168.233   # Write server IP on here

Host wayne-os2
  HostName 172.22.168.234   # Write server IP on here
~~~

## Reference
https://www.chromium.org/chromium-os/testing/autotest-developer-faq/ssh-test-keys-setup
