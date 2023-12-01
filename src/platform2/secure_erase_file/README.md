# Secure Erase File tool

The Chrome OS "secure_erase_file" package contains utilities for securely
erasing data stored on eMMC devices.

Its primary intended use is for erasing vault keyset data used by [cryptohome]
when transitioning to developer mode.

eMMC devices may provide commands for securely erasing data from the underlying
NAND flash, as described in [eMMC 5.1]. It is necessary to use these when
securely erasing data as the flash translation layer is free to map writes to
the same LBA to different underlying physical locations (e.g. wear-leveling).

By default, `secure_erase_file` will erase files using eMMC commands, write
zeroes over the target LBAs, unlink the file, and drop filesystem caches. It
will exit with a non-zero exit code if any of these operations fail for any
file.

This tool currently only supports eMMC devices; SATA and NVMe support may be
added in the future.

# Library interface: libsecure_erase_file

libsecure_erase_file is a small library that provides a C++ API. In order to
use the library in a package, you need to do the following:

- Add a dependency (`DEPEND` and `RDEPEND`) on chromeos-base/secure-erase to the
  package's ebuild.

- Link the package with libsecure_erase_file (for example, by passing
  `-lsecure_erase_file` to the package's link command).
  `libsecure_erase_file.so` is built and installed into the sysroot libdir
  (e.g. `$SYSROOT/usr/lib`).

- To access the secure_erase_file API in the package, include the
  `<secure_erase_file/secure_erase_file.h>` header file. The file is installed
  in `$SYSROOT/usr/include` when the library is built and installed.

# Binary interface: secure_erase_file

`secure_erase_file` is an executable which can be used to securely erase files
from shell scripts. To use it in a package, you need to do the following:

- Add a dependency (RDEPEND) on chromeos-base/secure-erase to the
  package's ebuild.

- The executable will be available at `/usr/bin/secure_erase_file`, but the path
  should be omitted by users. Just use `secure_erase_file`.

[cryptohome]: ../cryptohome/
[eMMC 5.1]: https://www.jedec.org/standards-documents/results/jesd84-b51
