# SELinux policy for Chrome OS

SELinux policy for Chrome OS lives here.

## Directory structure:

` platform2/sepolicy`
- `|- policy` SELinux policies live here. It contains sids, access vectors, mls,
  security classes, users, and roles definitions, type definitions, necessary
  macros for policy writing, and AVC rules.
  - `|- base` sids, access vectors, mls, security classes, users, roles
    definitions. fs_use, and genfs definitions. fs_use defines context for
    different filesystems, e.g, devtmpfs -> u:object_r:device:s0, ext4 ->
    u:object_r:labeledfs:s0. genfscon defines file labels from the policy (so no
    need to xattr actual inode), mostly for procfs.
  - `|- chromeos` All Chrome OS AVCs except for those in chromeos_base live
    here. Chrome OS file type definitions also live here.
    - `|- te_macros` Chrome OS-specific macros to write .te files, excluding
    those in `policy/base` or in `shared`.
    - `|- attributes` Chrome OS attributes.
    - `|- file.te` Chrome OS file labels.
    - `|- **.te` AVC rules for different domains.
  - `|- chromeos_base` minijail, cros_init, and cros init script domains live
    here. Inside structure similar to `chromeos`.
  - `|- mask_only` an NO-OP mask to make sure (base + mask_only) combined is a
    valid monotlithic policy.
- `|- file_contexts` file labels on system image, stateful partition, devtmpfs,
 sysfs live here.
- `\- shared` shared macros live here.

## Docs

Docs are located at
[chromiumos/docs/security/selinux.md](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/security/selinux.md)
