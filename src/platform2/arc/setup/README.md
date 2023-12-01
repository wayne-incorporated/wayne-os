# Chrome OS arc-setup.

## `/usr/sbin/arc-setup`

`arc-setup` handles setup/teardown of ARC container or upgrading container.
For example, mount point creation, directory creation, setting permissions uids
and gids, selinux label setting, config file creation.

Often, script language is used for such stuff in general, but ARC uses native
executable just for performance and better testability.

## `/usr/share/arc-setup/config.json`

`config.json` is the configuration file for `arc-setup`. Currently, the
following configurations are in the file:

### `ANDROID_DEBUGGABLE`

Setting this value to `true` will make Android boot with `ro.debuggable`. This
should make Android behave *mostly* like an -userdebug image.

A non-comprehensive list of caveats:

* Anything that detects the build type at compile-time will be unaffected, in
  particular SELinux rules that are relaxed, or the conditional compilation of
  some system tools.
* `adb root` will still be unavailable.
* `su` will be missing.
* `strace` won't work.
* The build type will still be -user.

### `WRITABLE_MOUNT`

Setting this value to `true` will make the Android root, and images for sdcard
etc. filesystems read-write. Note that the images themselves need to be in a
format that supports being mounted this way (e.g. ext4), which is not true of
the default format (squashfs).

## `config.json` and build/debug scripts

Several scripts modify the variables in `config.json`:

* `board_specific_setup.sh` rewrites `ANDROID_DEBUGGABLE` at image build time.
* `setup_writable_android_mount.sh` which is a debug script in Android
  repository rewrites `WRITABLE_MOUNT`.

Be careful when adding, removing, or renaming the entries.
