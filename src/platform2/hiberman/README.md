# Hiberman - The Hibernate Manager

This package implements the Hibernate Manager, a userspace system utility that
orchestrates hibernate and resume on ChromeOS.

## What is hibernate

At a high level, hibernate is a form of suspend that enables better power
consumption levels than suspend to RAM at the cost of additional entrance and
exit latency. In a traditional suspend, the CPUs are powered off, but RAM
remains powered on and refreshing. This enables fast resume times, as only the
CPU and device state need to be restored. But keeping RAM powered on and
refreshing comes with a cost in terms of power consumption. Hibernate is a form
of suspend where we also power down RAM, enabling us to completely shut down the
system and save more power. Before going down, we save the contents of RAM to
disk, so it can be restored upon resume. The contents of RAM here contain every
used page, including the running kernel, drivers, applications, heap, VMs, etc.
Note that only used pages of RAM need actually be saved and restored.

## How the kernel hibernates

From the kernel's perspective, the traditional process of suspending for
hibernation looks roughly like this:

 * All userspace processes are frozen
 * The kernel suspends all devices (including disks!) and all other CPUs
 * The kernel makes a copy of all in-use RAM, called a "snapshot", and keeps
   that snapshot in memory
 * The kernel resumes all devices
 * The snapshot image is written out to disk (now that the disk is no longer
   suspended)
 * The system enters S4 or shuts down.

The system is now hibernated. The process of resuming looks like this:

 * The system is booted, in an identical manner to a fresh power on
 * The kernel is made aware that there is a hibernate image (traditionally
   either by usermode or a kernel commandline argument)
 * The hibernate image is loaded back into memory
   * Some pages will be restored to their rightful original location. Some
     locations that need to be restored may already be in use by the currently
     running kernel. Those pages are restored to temporary RAM pages that are
     free in both the hibernated kernel and the current kernel.
 * All userspace processes are frozen
 * The kernel suspends all devices and all other CPUs
 * In a small stub, the kernel restores the pages that were previously loaded
   into temporary RAM locations, putting them in their final location. At this
   point, the kernel is committed to resume, as it may have overwritten large
   chunks of itself doing those final restorations.
 * Execution jumps to the restored image
 * The restored image resumes all devices and all other CPUs
 * Execution continues from the usermode process that requested the hibernation

## How hiberman hibernates

The steps in the previous section outline what a traditional kernel-initiated
hibernation looks like. Hiberman gets a little more directly involved with this
process by utilizing a kernel feature called userland-swsusp. This feature
exposes a snapshot device at /dev/snapshot, and enables a usermode process to
individually orchestrate many of the steps listed above. This has a number of
key advantages for ChromeOS:

 * The hibernate image can be encrypted with a key derived from user
   authentication (eg the user's password and the TPM)
 * Image loading can be separated from image decryption, allowing us to
   frontload disk I/O latency while the user is still authenticating
 * The methods used for storing and protecting the image don't have to be
   generalized to the point of being acceptable to the upstream kernel community

With this in mind, hiberman will do the following to hibernate the system:

 * Load the public hibernate key, which is specific to the user and machine.
   Generation of this key is described later.
 * Activate or create a new logical volume, "hibervol", formatted with ext4,
   where hibernate metadata will be stored. This includes logs, the hibernate
   image itself, and any data that may need to be passed through a successful
   resume. This logical volume must be fully provisioned, as holes in the thin
   volume might cause thinpool metadata to change in resume, invalidating the
   hibernated kernel's view of the thinpool.
 * Preallocate file system files in the hibervol LV, using fallocate() to
   ensure the file system has assigned space for all file extents.
 * Attempt to allocate, fault in, and free a large chunk of RAM, increasing the
   likelihood that enough RAM will be free to create the hibernate snapshot.
 * Generate a random symmetric key, which will be used to encrypt the hibernate
   image
 * Freeze all other userspace processes, and begin logging to a file
 * Ask the kernel to create its hibernate snapshot
 * Write the snapshot out to the disk space underpinning the preallocated file,
   encrypting it using the random symmetric key
 * Encrypt the random symmetric key using the public key. Save the result along
   with some other metadata like the image size into a preallocated metadata
   file.
 * Set a cookie at a known location towards the beginning of the disk indicating
   there's a valid hibernate image
 * Shut the system down (power state S5)
   * For devices with Intel KeyLocker, system enter power state S4

Resume is slightly harder to follow, because there is the "resume" path, the
"failed resume" path, and the "no resume" path:

 * The system powers on like any other boot. AP firmware runs, the Chrome ball
   delights our senses, and chromeos_startup runs
 * chromeos_startup calls out to hiberman to perform very early resume
   initialization. This resume-init command reads the hibernate cookie at the
   beginning of the disk to determine if it should initiate a resume, prepare to
   complete an interrupted abort, or do nothing if this is a totally fresh boot.
 * From here, things fork into two paths. In the "resume path":
   * At this time, the hibernate cookie is set, indicating there is a valid
     hibernate image the system may want to resume to.
   * The hibernate cookie is altered in resume-init to indicate a resume attempt
     started, and should not be retried in case of a crash.
   * Instead of mounting the stateful partition with read/write permissions, a
     dm-snapshot device is created on top of each logical volume used at resume
     time (at least unencrypted, dev-image, and encstateful), and the snapshot
     is mounted instead of the raw device.
     * Reads hit the real stateful volume, but writes are transparently diverted
       into a snapshot area, which is a regular file in the hibernate volume.
     * This is done to avoid modifying mounted file systems, which the
       hibernated kernel will assume have not changed out from under it.
   * Hiberman is invoked with the "resume" subcommand by upstart, sometime
     around when boot-services start.
     * Hiberman will load the unencrypted portion of the hibernate metadata,
       which contains untrusted hints of the image size and header pages
     * Hiberman will divert its own logging to a file, anticipating a successful
       resume where writes from this boot are lost
     * The header pages can be loaded into the kernel early, causing the kernel
       to allocate its large chunk of memory to store the hibernate image.
     * Hiberman will begin loading the hibernate image into its own process
       memory, as a way to frontload the large and potentially slow disk read
       operation.
     * Eventually hiberman will either load the whole image, or will stop early
       to prevent the system from becoming too low on memory. At this point,
       hiberman blocks and waits
   * Boot continues to Chrome and the login screen.
   * The user authenticates (for example, typing in their password and hitting
     enter)
     * If the user who logs in is not the same as the user who hibernated, the
       hibernated image is discarded, the snapshots are merged into the
       stateful partition on disk, and future writes go directly to the stateful
       partition.
     * The rest of this section assumes the user who logs in is the same user
       that hibernated.
   * At the point where Chrome has completed user authentication, but before
     cryptohome has mounted the users home volume, Chrome calls out to hiberman
     to initiate resume, handing it the in-progress auth session ID.
   * Hiberman uses this auth session ID to ask cryptohome for the secret
     hibernate seed, which is currently a derivative of the encrypted file
     system keys.
   * Hiberman uses the secret seed it got from cryptohome to derive the private
     key corresponding to the public key used at the beginning of hibernate.
   * Hiberman uses the private key to decrypt the private portion of the
     metadata.
   * Hiberman validates the hash of the header pages in the private metadata
     against what it observed while loading earlier. Resume is aborted if these
     don't match, or if other unverified parameters it's used so far don't
     match.
   * Hiberman gets the random symmetric key used to encrypt the image
   * Hiberman can then push the now-mostly-in-memory hibernate image into the
     kernel (through the snapshot device), decrypting as it goes
   * Hiberman freezes all usermode processes except itself
   * Hiberman asks the kernel to jump into the resumed image via the atomic
     restore ioctl
     * Upon success, the resumed image is now running
     * Upon failure, hiberman begins "abort" procedures. It starts by writing a
       new value to the hibernate cookie, indicating an abort is in progress.
     * Hiberman requests the system merge the dm-snapshots back to their
       respective origins.
     * If an unexpected reboot happens during this process, the snapshots are
       re-wired up by resume-init, and the resume process jumps directly to this
       abort path to continue the merge and abort.
     * Once the merges are completed, the hibernate cookie is fully reset to
       indicate no action is in progress.
 * In the "no resume" path, where there is no valid hibernate image:
   * The cookie is currently not set, so the stateful logical volumes are
     activated in R/W mode and mounted normally.
   * Hiberman is still invoked with the "resume" subcommand during init
     * Common to the successful resume case, hiberman attempts to read the
       metadata file, but discovers there is no valid image to resume
     * Also common to the successful resume case, hiberman blocks waiting for
       its secret key material
     * Eventually, a user logs in
     * Chrome makes its same call after login, and hiberman uses that info to
       request the secret seed from cryptohome.
     * Hiberman computes the asymmetric hibernate key pair, but discards the
       private portion
     * The public portion is saved in a ramfs file, to be used in the first step
       of a future hibernate

Upon a successful resume, the tail end of the hiberman suspend paths runs. It
does the following:
 * Unfreezes all other userspace processes
 * Reads the suspend and resume log files from disk, and replays them to the
   syslogger
 * Replays and sends off metrics
 * Exits

## Wrinkles and Constraints

### Half of memory

In the description of how the kernel hibernates, you'll notice that the kernel
creates the hibernate snapshot image in memory, but that image itself represents
all of used memory. You can see the challenge here with storing the contents of
memory in memory. The constraint that falls out of this mechanism is that at
least 50% of RAM must be free for the hibernate image to be successfully
generated (at best you can store half of memory in the other half of memory).

In cases where more than 50% of RAM is in use when hibernate is initiated, swap
comes to the rescue. When the kernel allocates space for its hibernate image,
this forces some memory out to swap.

### No RW mounts

Another interesting challenge presented by hibernate is the fact that the
hibernated image maintains active mounts on file systems. This means that in
between the time the snapshot is taken, and when it's been fully resumed,
modifications to areas like the stateful partition are not allowed. If this is
violated, the resumed kernel's in-memory file system structures will not be
consistent with what's on disk, likely resulting in corruption or failed
accesses.

This presents a challenge for the entire resume process, which consists of
booting Chrome all the way through the login prompt in order to get the
authentication-derived asymmetric key pair. To get this far in boot without
modifying mounted file systems, we utilize dm-snapshot (not to be confused with
the hibernate snapshot). With dm-snapshot we can create a block device where
reads come from another block device, but writes are diverted elsewhere. This
gives the system the appearance of having a read/write file system, but in this
case all writes are diverted to a loop device backed by a file on the hibernate
logical volume. Upon a successful resume, all writes to stateful file systems
that happened during this resume boot are effectively lost. It's as if that
resume boot never happened, which is exactly what the hibernated kernel needs.
Upon a failed or aborted resume, we merge the snapshot writes back down to the
stateful volumes. Once this is complete, we transparently rearrange the dm
table so that future writes go directly to the stateful volumes, instead of
diverting elsewhere.

One constraint of the dm-snapshot approach is that it's important that nothing
attempts to write huge amounts of data to the stateful volumes, since the
snapshot regions are reserved upfront and therefore limited in size. Most
components are quiet before any user has logged in, but system components like
update_engine, ARCVM, and LaCros will need to be aware of hibernate resume
boots. Hiberman will continually monitor the snapshots, and will abort the
resume and initiate the merge if the snapshots fill beyond a threshold
percentage.

### Saving hibernate state

There's another side effect of not being able to touch the stateful file system
after the hibernate snapshot is created: where do we store the hibernate image
and metadata itself?

In an old traditional disk partitioning scheme, the partition layout is fixed at
build time and very challenging to change once set up. The Logical Volume
Manager (LVM) allows straightforward dynamic creation and destruction of logical
volumes that effectively work like partitions. ChromeOS uses a "thinpool" to
support logical volumes, meaning that storage space from the underlying disk
isn't reserved until a process tries to write to a previously unused region of a
logical volume.

This is both a blessing and a complication. On the plus side, we can create a
hibernation logical volume at hibernate time, correctly sized to the exact
amount of RAM installed on the system (as the size of the hibernate image is
directly proportional to the size of RAM). If the user is crunched for space,
this volume can even be deleted after resume, allowing the user to completely
fill their disk (at the expense of future hibernations). We can use this volume
as the dm-snapshot delta backing store as well, giving us resilience against
unexpected power loss while a snapshot merge is in progress.

On the complexity side, the fact that the hibernate metadata lives "on top of"
LVM means that installing a single dm-snapshot for the entire physical volume
doesn't cut it. A dm-snapshot underneath LVM would make the entire disk
read-only, where we need the hibernate metadata to be writable even in resume.
So instead, we install dm-snapshots for each activated logical volume. This
means activation of new LVs during the resume process must be carefully
controlled, as activating and writing to an LV without a snapshot on top would
invalidate the resumed kernel's view of that volume (and potentially the entire
thinpool). The thinpool metadata itself may not change during the resume, as
that would also surprise the resumed kernel. So the hibernate logical volume
needs to be fully provisioned up front, so it does not attempt to
demand-allocate space during resume. Since cryptohome activates per-user LVs as
part of its mount process, the window during which Chrome must call into
hiberman is fairly precise (after auth, but before mount).

#### Hibernate DiskFiles

Even with its own logical volume formatted with ext4, hiberman cannot use
regular file access APIs to read and write data during hibernation in resume.
Hiberman operates in certain zones where all other tasks are frozen, including
kernel file system helper threads. Attempts to do a regular file write
operations usually result in hangs waiting for frozen kernel threads.

What we do instead is to essentially use ext4 as a disk area reservation system.
Towards the beginning of the hiberate process, we preallocate files, sized to
the maximum space we'll need. We use the fallocate() system call to both size
the file appropriately, and ensure that disk space is completely committed for
the whole file (in other words, there are no "holes" in the file). We then use
the FIEMAP ioctl to get the file system to report the underlying disk regions
backing the file. With that information, we can read and write directly to the
volume at those regions. The file system sees those extents as "uninitialized"
(since the file system has only reserved space for them, not written to them),
and makes no assumptions about the contents of those areas. By avoiding regular
file APIs and using O_DIRECT, hiberman minimizes it chances of getting blocked
on some frozen kernel helper task.

We use these "disk files" both to save the hibernate data and metadata, and to
pass logging information through from the suspend and resume process into the
final resumed system. We must be careful to operate on the volume with flags
(O_DIRECT) that ensure the kernel won't cache the disk content, giving us stale
reads on resume.

## Nickel Tour

Below is a quick overview of the code's organization, to help readers understand
how the app is put together:

 * main.rs - The entry point into the application. Handles command line
   processing and calling out to the main subcommand functions.
 * hiberman.rs - The main library file. It contains almost nothing but a couple
   wrappers to call other modules that do the real work, and a list of
   submodules within the library.
 * suspend.rs - Handles the high level orchestration of the suspend process
 * resume_init.rs - Handles the very early resume initialization prep, such as
   checking the cookie and setting up the dm-snapshots for stateful volumes.
 * resume.rs - Handles the high level orchestration of the resume process
 * cat.rs - Handles the cat subcommand
 * cookie.rs - Handles the cookie subcommand and functionality

The rest of the files implement low level helper functionality, either an
individual component of the hibernate process or a collection of smaller
helpers:

 * crypto.rs - Handles bulk symmetric encryption of the big hibernate data image
 * dbus.rs - Handles dbus interactions
 * diskfile.rs - Provides a Read, Write, and Seek abstraction for "disk files",
   which operate directly on the partition areas underneath a particular file
   system file.
 * fiemap.rs - Provides a friendlier interface to the fiemap ioctl, returning the
   set of extents on disk which comprise a file system file. This is used by the
   DiskFile object to get disk information for a file.
 * files.rs - A loose collection of functions that create or open the stateful
   files used by hibernate. Possibly to be overridden during testing.
 * hiberlog.rs - Handles the more-complicated-than-average task of logging. This
   module can store logs in memory, divert them to a DiskFile, push them out to
   the syslogger, and/or write them to /dev/kmsg.
 * hibermeta.rs - Encapsulates management of the hibernate metadata structure,
   including loading/storing it on disk, and encrypting/decrypting the private
   portion.
 * hiberutil.rs - A miscellaneous grab bag of functions used across several
   modules.
 * imagemover.rs - The "pump" of the hibernate image pipeline, this is the
   component calling read() and write() to move data between two file
   descriptors.
 * keyman.rs - Encapsulates creation and management of the asymmetric key pair
   used to protect the private hibernate metadata.
 * lvm.rs - Helper functions for dealing with LVM.
 * metrics.rs - Handles saving and replaying metrics throughout the hibernate
   and resume process.
 * mmapbuf.rs - A helper object to create large aligned buffers (which are a
   requirement for files opened with O_DIRECT).
 * powerd.rs - Handles interactions with the ChromeOS power daemon.
 * snapdev.rs - Encapsulates ioctl interactions with /dev/snapshot.
 * splitter.rs - An object that can be inserted in the image pipeline that
   splits or merges the snapshot data into a header portion and a data portion.
 * sysfs.rs - A miscellaneous file for temporarily modifying sysfs files during
   the hibernate process.
 * volume.rs - Handles volume-related operations, such as setting up
   dm-snapshots, merging them, mounting volumes, etc.
