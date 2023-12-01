This feature profile enables the debug and kcov USE flags for every chromeos-kernel
package. It is intended to be used for CrOS automated debug kernel testing
(go/cros-automated-debug-kernel-testing) and go/ctp-syzkaller.

Debug kernel testing is designed to uncover bugs that are hidden in our
regularly tested kernel which is optimized for performance. Enabling the kernel
debug flag will turn on necessary assertions and debug options to expose such
bugs. USE=kcov must be enabled to run Syzkaller on lab DUTs for go/ctp-syzkaller.

To add a debug kernel profile to an existing overlay, take the following steps:
1) Create a new subdirectory within the given overlay's "profiles" directory.
2) Add a "parent" file to the new subdirectory with the below two lines:
  ```
  ../base
  chromiumos:features/kernel/debug
  ```

The first line specifies that the new profile will inherit from the overlay's
base profile. The second line will mix in this debug feature profile which
enables the debug and kcov USE flags for the chromeos-kernel package, independent of
which kernel version the overlay uses.
