# Process Killer

`process_killer` is a utility to search for and kill processes that might hold
up the tearing down and safe unmounting of stateful storage mounts/devices.
On ChromeOS, the mounts/devices of interest include any encrypted storage
mount/device (eg. cryptohome mounts, encrypted stateful partition's dm-crypt
device) as well as the stateful filesystem.

`process_killer` looks for the following types of processes:
* Processes that have files open on matching paths of interest (controlled by
  the CLI option `--file_holders`).
* Processes that have mounts open from devices of interest in a cloned mount
  namespace (controlled by the CLI option `--mount_holders`). Such processes
  don't prevent clean unmounts in the init mount namespace but will still
  hold a reference to the mount (and by extension, the filesystem
  superblock/underlying block device) during end of session and shutdown.

`process_killer` is currently used in the following situations:

* **Session End** (`ui-post-stop`): At end of the session, `process_killer` is
  used to first find processes that have files open into the user
  cryptohome. This allows cryptohome a shot into safely unmounting all encrypted
  user mounts. As a failsafe, cryptohome falls back to doing a lazy unmount.
  Finally, `process_killer` is called as a last resort for processes still
  holding user cryptohome mounts in a cloned MS_PRIVATE mount namespace.
* **System Shutdown** (`chromeos_shutdown`): At shutdown, `process_killer` is
  used as a last resort to kill any service still accessing stateful mounts.
  Barring misconfigured init scripts, few processes are running at shutdown
  so `process_killer` does a final sweep of all file and mount holders
  before starting the teardown process for the stateful mounts.
