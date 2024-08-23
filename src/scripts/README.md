## Package modification notice
#### Purpose
- Modifying waiting time of the bootloader
- Admin PW for test version

#### Modified files
- build_library/create_legacy_bootloader_templates.sh
- mod_for_test_scripts/300changePassword
- README.md

#### Modifier
- seongbin@wayne-inc.com


# `src/scripts` directory

This repository contains build tools and scripts written in shell (e.g., Bash).
Historically, much of our build process was written in shell in this directory,
however, we're currently in the process of migrating many scripts to Python in
[Chromite].

In general, we're not currently accepting new scripts in this directory.

If you want to host a script for yourself/local team, feel free to use the
src/platform/dev/contrib/ directory instead.

[Chromite]: https://chromium.googlesource.com/chromiumos/chromite
