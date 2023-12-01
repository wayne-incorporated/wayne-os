# Pid 1 (init)

`maitred` provides init-like functionality for processes inside the VM.

## Early setup
`maitred` performs some early setup before it begins listening for rpcs from the
host.  This includes mounting various filesystems (like `proc`, `sysfs`, and
`cgroups`).  Additionally `maitred` mounts a `tmpfs` on the `/tmp` and `/run`
directories so that applications can have temporary runtime storage.

## Launching processes

New processes can either be spawned by sending `maitred` a `LaunchProcess` rpc
or by placing `.textproto` files in `/etc/maitred`. Both methods use the
`LaunchProcessRequest` message, which can be found in
the [vm_guest.proto](../proto/vm_guest.proto) file.

`maitred` will then follow the lifetime of this process until it exits or is
killed by a signal.  If the `LaunchProcessRequest` message indicated that the
process should be respawned, then `maitred` will launch a new instance of that
process.  However, processes that respawn more than 10 times in 30 seconds will
be stopped.  These processes can only be restarted by sending another
`LaunchProcess` rpc.

Processes in the `/etc/maitred` folder will be alphabetically sorted and
started. Process files follow the naming convention
`##-processname.textproto` where `##` defines the starting order. e.g
`00-setup-process.textproto` will start before `10-main-process.textproto`.
Make sure to use a two digits prefix, or you might run into unexpected behavior.
e.g. `100-process.textproto` will start before `90-setup-process.textproto`.
If a first process must start before a second, the first process will have to
have the `wait_for_exit` flag set in the `LaunchProcessRequest` message.

To launch a VM and without any of the processes in the /etc/maitred folder,
you can provide a kernel parameter - `maitred.no\_startup\_processes`.
Once the VM is launched, it will accept `LaunchProcess` rpcs like normal.

### Process Privileges

Processes launched by `maitred` run as root with full privileges.  If the sender
of the `LaunchProcess` rpc does not want that process to have full root access,
then they should ensure that the program either uses `libminijail` to drop
privileges or launch the program using `minijail0` with the appropriate flags.

## Shutting down

When `maitred` receives a `Shutdown` rpc, it sends a `SIGTERM` signal to all
processes running on the VM.  After 5 seconds it terminates any remaining
processes by sending them a `SIGKILL` signal.

`maitred` then shuts down the system by issuing a `reboot` system call.

### Cleaning up during shutdown

Some processes may wish to perform some clean up before the system is shut down.
For example `vm_syslog` will want to flush any buffered logs before shut down.
These processes should catch the SIGTERM signal sent out by `maitred`, perform
any clean up, and then exit.
