# Chromium OS Secure Wipe

Full disk wipe code for factory and recovery images.

Due to indirection performed by flash storage firmware (e.g. for the purpose of
wear leveling) there is no constant mapping between the underlying backing store
and the storage sectors exposed at the block layer. As a consequence, the only
reliable way to delete any piece of data from a flash storage device is to clear
the entire backing store. This package implements full disk deletion for SATA,
eMCC and NVMe.

In principle, this package should provide stronger guarantees than
secure_erase_file because the latter only erases the backing store at the file's
*current* location (which may be different from past locations) whereas
disk-wipe deletes the entire backing store.

Caveat emptor: While sanity checks will be put in place, there is no way to
guarantee that the deletion interface called by the disk wipe code is correctly
implemented by the storage device.
