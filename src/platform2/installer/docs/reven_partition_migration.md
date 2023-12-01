# Reven partition migration

Reven is the ChromeOS Flex board. Many ChromeOS Flex installations are
upgrades from CloudReady. For [historical reasons][legacy_disk_layout],
CloudReady had 16MiB KERN-A and KERN-B partitions.  It's not possible to
apply an update with, for example, a 32MiB kernel partition onto an
image with 16MiB kernel partitions, so Reven's disk layout also
specifies 16MiB kernel partitions.

The 16MiB kernel partitions are getting a little tight on disk space for
various reasons, so we need to increase the size of the Reven kernel
partitions. Other boards currently use 32MiB kernel partitions ([v2
layout], [v3 layout]). To be reasonably future proof, we are increasing
the size of Reven's kernel partitions to 64MiB.

We can't just directly increase the size in the disk layout because it
would break all updates. Instead we'll do a live migration that makes
use of unused space at the end of the root partitions. Each root
partition is 4GiB (or 3GiB if updating from CloudReady), but the actual
amount of space used is smaller. We can safely steal the last 64MiB of
blocks from each root partition and use it for the new kernel
partitions.

The migration in more detail:

1. The migration occurs during postinstall.
2. A migration plan is created by looking at the disk layout. Both the A
   and B slots are examined. If the kernels are already 64MiB, no
   migration is needed.
3. If a migration is needed, new kernel regions are defined at the end
   of the current root partitions. The existing 16MiB of kernel data are
   copied to the new location, and the rest is zeroed.
4. The GPT headers are updated to shrink the root partitions, and update
   the location and size of the kernel partitions.

To limit the initial scope of testing, the migration will be run for all
fresh installs, but not for all updates. In particular, only test images
and images on the canary/dev channels will run the migration on update. That
means fresh installations will always have 64MiB kernel partitions, but
upgraded installations may still have 16MiB kernel partitions for
now. Once we're confident that this is working well, we'll expand the
scope of the migration to more updates, potentially with a
[trial][featured] in place to roll out the change slowly. Once we're
confident in that rollout, we'll mark a release as a "stepping-stone"
update so that no devices can update to a release after that one without
first passing through the stepping-stone update. After that we know that
all devices have 64MiB kernel partitions, so we'll be able to update the
disk layout to 64MiB. At that point we can also drop this migration
code.

The implementation for the migration is in
[`reven_partition_migration.cc`]. Note that the migration code is only
included if the `reven_partition_migration` USE flag is enabled,
otherwise [`reven_partition_migration_stub.cc`] is built instead.

[`reven_partition_migration.cc`]: ../reven_partition_migration.cc
[`reven_partition_migration_stub.cc`]: ../reven_partition_migration_stub.cc
[featured]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/featured
[legacy_disk_layout]: https://chromium.googlesource.com/chromiumos/platform/crosutils/+/HEAD/build_library/legacy_disk_layout.json
[v2 layout]: https://chromium.googlesource.com/chromiumos/platform/crosutils/+/HEAD/build_library/disk_layout_v2.json
[v3 layout]: https://chromium.googlesource.com/chromiumos/platform/crosutils/+/HEAD/build_library/disk_layout_v3.json
