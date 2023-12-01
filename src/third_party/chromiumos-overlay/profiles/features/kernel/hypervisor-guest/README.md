This feature profile enables the hypervisor_guest USE flags for every
chromeos-kernel package. It speeds up CrOS running as a guest on hypervisor.

To add this profile to an existing overlay, take the following steps:
1) Create a new subdirectory within the given overlay's "profiles" directory.
2) Add a "parent" file to the new subdirectory with the below two lines:
  ```
  ../base
  chromiumos:features/kernel/hypervisor-guest
  ```

The first line specifies that the new profile will inherit from the overlay's
base profile. The second line will mix in this profile which enables the
hypervisor_guest USE flags for the chromeos-kernel package, independent of
which kernel version the overlay uses.
