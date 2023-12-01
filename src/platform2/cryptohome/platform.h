// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_PLATFORM_H_
#define CRYPTOHOME_PLATFORM_H_

#include <stdint.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback_forward.h>
#include <base/unguessable_token.h>
#include <brillo/blkdev_utils/loop_device.h>
#include <brillo/blkdev_utils/lvm.h>
#include <brillo/brillo_export.h>
#include <brillo/process/process.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest_prod.h>

extern "C" {
#include <keyutils.h>
#include <linux/fs.h>
}

#include "cryptohome/dircrypto_util.h"

#ifndef EXT4_EOFBLOCKS_FL
/*
 * Older kernel were using this bit to help cleanup.
 * Deprecated in 5.10 and beyond, it may not be present in kernel
 * includes anymore.
 * Make sure it is defined to we can omit when setting extended files
 * attributes.
 */
#define EXT4_EOFBLOCKS_FL 0x00400000
#endif

namespace base {
class Thread;
class Time;
}  // namespace base
namespace crossystem {
class Crossystem;
}  // namespace crossystem

namespace cryptohome {

// The extension for the checksum files.
inline constexpr char kChecksumExtension[] = "sum";

// Default umask
inline constexpr const int kDefaultUmask =
    S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH;

// Default mount flags for Platform::Mount.
inline constexpr const uint32_t kDefaultMountFlags =
    MS_NOEXEC | MS_NOSUID | MS_NODEV;

// Loop devices prefix.
BRILLO_EXPORT extern const char kLoopPrefix[];

// IDs of necessary groups and users
inline constexpr uid_t kRootUid = 0;
inline constexpr gid_t kRootGid = 0;
inline constexpr gid_t kDaemonStoreGid = 400;
inline constexpr uid_t kChronosUid = 1000;
inline constexpr gid_t kChronosGid = 1000;
inline constexpr gid_t kChronosAccessGid = 1001;

// Decoded content of /proc/<id>/mountinfo file that has format:
// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root .. // nocheck
// rw,errors= (0)(1)(2)   (3)   (4)      (5)      (6)   (7) (8)   (9) (10)
struct DecodedProcMountInfo {
  // (3) The pathname of the directory in the filesystem which forms the root of
  // this mount.
  std::string root;
  // (4) The pathname of the mount point relative to the process's root
  // directory.
  std::string mount_point;
  // (8) The filesystem type in the form "type[.subtype]".
  std::string filesystem_type;
  // (9) Filesystem-specific information or "none".
  std::string mount_source;
};

// List of return values of a mount expire operation.
enum class ExpireMountResult {
  kMarked,
  kUnmounted,
  kBusy,
  kError,

  // Must be the last item.
  kMaxValue = kError
};

// List of remount options.
enum class RemountOption {
  kNoRemount,
  kPrivate,
  kShared,
  kMountsFlowIn,  // Equivalent to MS_SLAVE
  kUnbindable,

  // Must be the last item.
  kMaxValue = kUnbindable
};

// A class for enumerating the files in a provided path. The order of the
// results is not guaranteed.
//
// DO NOT USE FROM THE MAIN THREAD of your application unless it is a test
// program where latency does not matter. This class is blocking.
//
// See base::FileEnumerator for details.  This is merely a mockable wrapper.
class BRILLO_EXPORT FileEnumerator {
 public:
  // Copy and assign enabled.
  class BRILLO_EXPORT FileInfo {
   public:
    explicit FileInfo(const base::FileEnumerator::FileInfo& file_info);
    FileInfo(const base::FilePath& name, const base::stat_wrapper_t& stat);
    FileInfo(const FileInfo& other);
    FileInfo();
    virtual ~FileInfo();
    FileInfo& operator=(const FileInfo& other);

    bool IsDirectory() const;
    base::FilePath GetName() const;
    int64_t GetSize() const;
    base::Time GetLastModifiedTime() const;
    const base::stat_wrapper_t& stat() const;

   private:
    void Assign(const base::FileEnumerator::FileInfo& file_info);

    std::unique_ptr<base::FileEnumerator::FileInfo> info_;
    base::FilePath name_;
    base::stat_wrapper_t stat_;
  };

  FileEnumerator(const base::FilePath& root_path,
                 bool recursive,
                 int file_type);
  FileEnumerator(const base::FilePath& root_path,
                 bool recursive,
                 int file_type,
                 const std::string& pattern);
  // Meant for testing only.
  FileEnumerator();
  virtual ~FileEnumerator();

  // Returns an empty file name if there are no more results.
  virtual base::FilePath Next();

  // Write the file info into |info|.
  virtual FileInfo GetInfo();

 private:
  std::unique_ptr<base::FileEnumerator> enumerator_;
};

// Platform specific routines abstraction layer.
// Also helps us to be able to mock them in tests.
class BRILLO_EXPORT Platform {
 public:
  struct Permissions {
    uid_t user;
    gid_t group;
    mode_t mode;
  };
  struct LoopDevice {
    base::FilePath backing_file;
    base::FilePath device;
  };

  Platform();
  Platform(const Platform&) = delete;
  Platform& operator=(const Platform&) = delete;

  virtual ~Platform();

  // Calls the platform mount
  //
  // Parameters
  //   from - The node to mount from
  //   to - The node to mount to
  //   type - The fs type
  //   mount_options - The mount options to pass to mount()
  virtual bool Mount(const base::FilePath& from,
                     const base::FilePath& to,
                     const std::string& type,
                     uint32_t mount_flags,
                     const std::string& mount_options);

  // Creates a bind mount
  //
  // Parameters
  //   from - Where to mount from
  //   to - Where to mount to
  //   remount - Which mount mode the bind mount should use. Some remount modes
  //   may have no effect as the transition depends on the original mode of the
  //   option. See
  //   https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt
  //   for more details.
  //   nosymfollow - Whether to apply nosymfollow on the mount.
  virtual bool Bind(const base::FilePath& from,
                    const base::FilePath& to,
                    RemountOption remount = RemountOption::kNoRemount,
                    bool nosymfollow = false);

  // Calls the platform unmount
  //
  // Parameters
  //   path - The path to unmount
  //   lazy - Whether to call a lazy unmount
  //   was_busy (OUT) - Set to true on return if the mount point was busy
  virtual bool Unmount(const base::FilePath& path, bool lazy, bool* was_busy);

  // Lazily unmounts |path|.
  //
  // Parameters
  //   path - The destination path to unmount
  virtual void LazyUnmount(const base::FilePath& path);

  // Calls the platform unmount with the flag MNT_EXPIRE.
  // This marks inactive mounts as expired and returns |kMarked|. Calling
  // `ExpireMount` on an expired mount point at |path| unmounts the mount point
  // and returns |kUnmounted|, if it has not been accessed since it was marked
  // as expired. Attempting to mark an active mount as expired fails with
  // EBUSY and returns |kBusy|. Returns |kError| for other unmount() errors.
  //
  // Parameters
  //   path - The path to unmount
  virtual ExpireMountResult ExpireMount(const base::FilePath& path);
  // Returns true if any mounts match. Populates |mounts| with list of mounts
  // from loop device to user directories that are used in ephemeral mode.
  //
  // Parameters
  //   mounts - matching mounted paths, can't be NULL
  virtual bool GetLoopDeviceMounts(
      std::multimap<const base::FilePath, const base::FilePath>* mounts);

  // Returns true if any mounts match. Populates |mounts| if
  // any mount sources have a matching prefix (|from_prefix|).
  //
  // Parameters
  //   from_prefix - Prefix for matching mount sources
  //   mounts - matching mounted paths, may be NULL
  virtual bool GetMountsBySourcePrefix(
      const base::FilePath& from_prefix,
      std::multimap<const base::FilePath, const base::FilePath>* mounts);

  // Returns true if any mounts match. Populates |mounts| with list of mounts
  // from devices with prefix |from_prefix|. Note that this differs from
  // GetMountBySourcePrefix, which applies to mounts which have a source
  // in another directory (eg. bind mounts, eCryptfs, overlayfs).
  //
  // Parameters
  //   from_prefix - Prefix for matching mount device
  //   mounts - matching mounted paths, can't be NULL
  virtual bool GetMountsByDevicePrefix(
      const std::string& from_prefix,
      std::multimap<const base::FilePath, const base::FilePath>* mounts);

  // Returns true if the directory is in the mount_info
  //
  // Parameters
  //   directory - The directory to check
  virtual bool IsDirectoryMounted(const base::FilePath& directory);

  // Returns true for each directory that is in the mount_info
  // On error returns an empty vector
  //
  // Parameters
  //   directories - The directories to check
  virtual std::optional<std::vector<bool>> AreDirectoriesMounted(
      const std::vector<base::FilePath>& directories);

  // Returns an instance of class brillo::Process that can be mocked out in
  // tests.
  virtual std::unique_ptr<brillo::Process> CreateProcessInstance();

  // Calls the platform stat() or lstat() function to obtain the ownership of
  // a given path. The path may be a directory or a file.
  //
  // Parameters
  //   path - The path to look up
  //   user_id - The user ID of the path. NULL if the result is not needed.
  //   group_id - The group ID of the path. NULL if the result is not needed.
  //   follow_links - Whether or not to dereference symlinks
  virtual bool GetOwnership(const base::FilePath& path,
                            uid_t* user_id,
                            gid_t* group_id,
                            bool follow_links) const;

  // Calls the platform chown() or lchown() function on the given path.
  //
  // The path may be a directory or a file.
  //
  // Parameters
  //   path - The path to set ownership on
  //   user_id - The user_id to assign ownership to
  //   group_id - The group_id to assign ownership to
  //   follow_links - Whether or not to dereference symlinks
  virtual bool SetOwnership(const base::FilePath& directory,
                            uid_t user_id,
                            gid_t group_id,
                            bool follow_links);

  // Calls the platform stat() function to obtain the permissions of
  // the given path. The path may be a directory or a file.
  //
  // Parameters
  //   path - The path to look up
  //   mode - The permissions of the path
  virtual bool GetPermissions(const base::FilePath& path, mode_t* mode) const;

  // Calls the platform chmod() function on the given path.
  // The path may be a directory or a file.
  //
  // Parameters
  //   path - The path to change the permissions on
  //   mode - the mode to change the permissions to
  virtual bool SetPermissions(const base::FilePath& path, mode_t mode);

  // Return the available disk space in bytes on the volume containing |path|,
  // or -1 on failure.
  // Code duplicated from Chrome's base::SysInfo::AmountOfFreeDiskSpace().
  //
  // Parameters
  //   path - the pathname of any file within the mounted file system
  virtual int64_t AmountOfFreeDiskSpace(const base::FilePath& path) const;

  // Returns the current space for the given uid from quotactl syscall, or -1 if
  // the syscall fails.
  //
  // Parameters
  //   device - The pathname to the block special device
  //   user_id - The user ID to query for
  virtual int64_t GetQuotaCurrentSpaceForUid(const base::FilePath& device,
                                             uid_t user_id) const;

  // Returns the current space for the given gid from quotactl syscall, or -1 if
  // the syscall fails.
  //
  // Parameters
  //   device - The pathname to the block special device
  //   group_id - The group ID to query for
  virtual int64_t GetQuotaCurrentSpaceForGid(const base::FilePath& device,
                                             gid_t group_id) const;

  // Returns the current space for the given project ID from quotactl syscall,
  // or -1 if the syscall fails.
  //
  // Parameters
  //   device - The pathname to the block special device
  //   project_id - The project ID to query for
  virtual int64_t GetQuotaCurrentSpaceForProjectId(const base::FilePath& device,
                                                   int project_id) const;

  // Gets the project ID of a file or directory at |path|.
  // Returns true if ioctl syscall succeeds.
  //
  // Parameters
  //   path - The path to the file or directory to get project ID
  //   project_id - Pointer to store the obtained project ID
  virtual bool GetQuotaProjectId(const base::FilePath& path,
                                 int* project_id) const;

  // Sets the project ID to a file or directory at |path|.
  // Returns true if ioctl syscall succeeds.
  //
  // Parameters
  //   path - The path to the file or directory to set project ID
  //   project_id - The project ID
  virtual bool SetQuotaProjectId(const base::FilePath& path, int project_id);

  // Sets the project ID to the FD.
  // Returns true if ioctl syscall succeeds.
  //
  // Parameters
  //   project_id - The project ID
  //   fd - The FD
  //   out_error - errno when ioctl fails
  virtual bool SetQuotaProjectIdWithFd(int project_id, int fd, int* out_error);

  // Sets or resets the Quota Inheritance flags on |fd|.
  // Returns true if ioctl syscall succeeds.
  //
  // Parameters
  //   enable - Whether we want to enable the project inheritance flag.
  //   fd - The FD
  //   out_error - errno when ioctl fails
  virtual bool SetQuotaProjectInheritanceFlagWithFd(bool enable,
                                                    int fd,
                                                    int* out_error);

  // Returns true if the specified file exists.
  //
  // Parameters
  //  path - Path of the file to check
  virtual bool FileExists(const base::FilePath& path) const;

  // Calls Access() on path with flag
  //
  // Parameters
  //   path - Path of file to access.
  //   flag -  Access flag.
  virtual int Access(const base::FilePath& path, uint32_t flag);

  // Check if a directory exists as the given path
  virtual bool DirectoryExists(const base::FilePath& path);

  // Provides the size of a file at |path| if it exists.
  //
  // Parameters
  //   path - Path of the file to check
  //   size - int64_t* to populate with the size
  // Returns true if the size was acquired and false otherwise.
  virtual bool GetFileSize(const base::FilePath& path, int64_t* size);

  // Returns the disk usage of a directory at |path| if it exists.
  // Note that this computes the disk space used/occupied by the directory,
  // instead of the apparent size.
  //
  // Parameters
  //   path - Path of the directory to check
  // Returns the directory disk usage in bytes.
  virtual int64_t ComputeDirectoryDiskUsage(const base::FilePath& path);

  // Opens a file, if possible, returning a FILE*. If not, returns NULL.
  //
  // Parameters
  //   path - Path of the file to open
  //   mode - mode string of the file when opened
  virtual FILE* OpenFile(const base::FilePath& path, const char* mode);

  // Closes a FILE* opened with OpenFile()
  //
  // Parameters
  //  fp - FILE* to close
  virtual bool CloseFile(FILE* fp);

  // Initializes a base::File.  The caller is responsible for verifying that
  // the file was successfully opened by calling base::File::IsValid().
  //
  // Parameters
  //   file - The base::File object to open the file in.
  //   path - Path of the file to open.
  //   flags - Flags to use when opening the file.  See base::File::Flags.
  virtual void InitializeFile(base::File* file,
                              const base::FilePath& path,
                              uint32_t flags);

  // Applies an exclusive advisory lock on the file.
  // The lock will be released when the file is closed.
  //
  // Parameters
  //  fd - File descriptor to lock.
  virtual bool LockFile(int fd);

  // Reads a file completely into a blob/string.
  //
  // Parameters
  //  path              - Path of the file to read
  //  blob/string (OUT) - blob/string to populate
  virtual bool ReadFile(const base::FilePath& path, brillo::Blob* blob);
  virtual bool ReadFileToString(const base::FilePath& path,
                                std::string* string);
  virtual bool ReadFileToSecureBlob(const base::FilePath& path,
                                    brillo::SecureBlob* sblob);

  // Writes the entirety of the given data to |path| with 0640 permissions
  // (modulo umask).  If missing, parent (and parent of parent etc.) directories
  // are created with 0700 permissions (modulo umask).  Returns true on success.
  //
  // Parameters
  //  path      - Path of the file to write
  //  blob/data - blob/string/array to populate from
  // (size      - array size)
  virtual bool WriteFile(const base::FilePath& path, const brillo::Blob& blob);
  virtual bool WriteSecureBlobToFile(const base::FilePath& path,
                                     const brillo::SecureBlob& blob);
  virtual bool WriteStringToFile(const base::FilePath& path,
                                 const std::string& data);
  virtual bool WriteArrayToFile(const base::FilePath& path,
                                const char* data,
                                size_t size);

  // Atomically writes the entirety of the given data to |path| with |mode|
  // permissions (modulo umask).  If missing, parent (and parent of parent etc.)
  // directories are created with 0700 permissions (modulo umask).  Returns true
  // if the file has been written successfully and it has physically hit the
  // disk.  Returns false if either writing the file has failed or if it cannot
  // be guaranteed that it has hit the disk.
  //
  // Parameters
  //   path - Path of the file to write
  //   data - Blob to populate from
  //   mode - File permission bit-pattern, eg. 0644 for rw-r--r--
  virtual bool WriteFileAtomic(const base::FilePath& path,
                               const brillo::Blob& blob,
                               mode_t mode);
  virtual bool WriteSecureBlobToFileAtomic(const base::FilePath& path,
                                           const brillo::SecureBlob& blob,
                                           mode_t mode);
  virtual bool WriteStringToFileAtomic(const base::FilePath& path,
                                       const std::string& data,
                                       mode_t mode);

  // Atomically and durably writes the entirety of the given data to |path| with
  // |mode| permissions (modulo umask).  If missing, parent (and parent of
  // parent etc.)  directories are created with 0700 permissions (modulo umask).
  // Returns true if the file has been written successfully and it has
  // physically hit the disk.  Returns false if either writing the file has
  // failed or if it cannot be guaranteed that it has hit the disk.
  //
  // Parameters
  //  path      - Path of the file to write
  //  blob/data - blob/string to populate from
  //  mode      - File permission bit-pattern, eg. 0644 for rw-r--r--
  virtual bool WriteFileAtomicDurable(const base::FilePath& path,
                                      const brillo::Blob& blob,
                                      mode_t mode);
  virtual bool WriteSecureBlobToFileAtomicDurable(
      const base::FilePath& path, const brillo::SecureBlob& blob, mode_t mode);
  virtual bool WriteStringToFileAtomicDurable(const base::FilePath& path,
                                              const std::string& data,
                                              mode_t mode);

  // Creates empty file durably, i.e. ensuring that the directory entry is
  // created on-disk immediately.  Set 0640 permissions (modulo umask).
  //
  // Parameters
  //   path - Path to the file to create
  virtual bool TouchFileDurable(const base::FilePath& path);

  // Delete the given path.
  //
  // Parameters
  //  path - string containing file path to delete
  virtual bool DeleteFile(const base::FilePath& path);

  // Delete the given path and the subtree recursively.
  //
  // Parameters
  //  path - string containing file path to delete
  virtual bool DeletePathRecursively(const base::FilePath& path);

  // Deletes file durably, i.e. ensuring that the directory entry is immediately
  // removed from the on-disk directory structure.
  //
  // Parameters
  //   path - Path to the file to delete
  virtual bool DeleteFileDurable(const base::FilePath& path);

  // Deletes file securely, ensuring that the data is removed from the
  // underlying media. Only works for supported mounts/devices.
  //
  // Parameters
  //   path - Path to the file to delete
  virtual bool DeleteFileSecurely(const base::FilePath& path);

  // Create a directory with the given path (including parent directories, if
  // missing). All created directories will have 0700 permissions (modulo
  // umask). Returns true on success without modifying |error|. Returns false on
  // failure and sets |error| appropriately. See
  // base::CreateDirectoryAndGetError() for details.
  //
  // Parameters
  //   path - Absolute path to the directory to create.
  //   error - Pointer to store the error code on failures. This can be null.
  virtual bool CreateDirectoryAndGetError(const base::FilePath& path,
                                          base::File::Error* error);

  // Backward-compatible convenience method for the above. Note that this does
  // not set |errno| correctly when it fails.
  // TODO(b/272704660): Set |errno| correctly.
  virtual bool CreateDirectory(const base::FilePath& path);

  // Enumerate all directory entries in a given directory
  //
  // Parameters
  //  path - root of the tree to enumerate
  //  is_recursive - true to enumerate recursively
  //  ent_list - vector of strings to add enumerate directory entry paths into
  virtual bool EnumerateDirectoryEntries(const base::FilePath& path,
                                         bool is_recursive,
                                         std::vector<base::FilePath>* ent_list);

  // Returns true if the directory is empty
  //
  // Parameters
  //  path - directory path
  virtual bool IsDirectoryEmpty(const base::FilePath& path);

  // Returns a new FileEnumerator instance.
  //
  // The caller TAKES OWNERSHIP of the returned pointer.
  //
  // Parameters
  // (see FileEnumerator())
  virtual FileEnumerator* GetFileEnumerator(const base::FilePath& root_path,
                                            bool recursive,
                                            int file_type);

  // Look up information about a file or directory
  //
  // Parameters
  //  path - element to look up
  //  buf - buffer to store results into
  virtual bool Stat(const base::FilePath& path, base::stat_wrapper_t* buf);

  // Return true if |path| has extended attribute |name|.
  //
  // Parameters
  //  path - absolute file or directory path to look up
  //  name - name including a namespace prefix. See getxattr(2).
  virtual bool HasExtendedFileAttribute(const base::FilePath& path,
                                        const std::string& name);

  // Add all extended attribute names on |path| to |attr_list|.
  //
  // Parameters
  //  path - absolute file or directory path to list attributes for.
  //  attr_list - vector to store attribute names in to.
  virtual bool ListExtendedFileAttributes(const base::FilePath& path,
                                          std::vector<std::string>* attr_list);

  // Return true if extended attribute |name| could be read from |path|,
  // storing the value in |value|.
  //
  // Parameters
  //  path - absolute file or directory path to get attributes for
  //  name - name including a namespace prefix. See getxattr(2)
  //  value - variable to store the resulting value in
  virtual bool GetExtendedFileAttributeAsString(const base::FilePath& path,
                                                const std::string& name,
                                                std::string* value);

  // Return true if extended attribute |name| could be read from |path|,
  // storing the value in |value|.
  //
  // Parameters
  //  path - absolute file or directory path to get attributes for
  //  name - name including a namespace prefix. See getxattr(2)
  //  value - pointer to store the resulting value in
  //  size - The expected size of the extended attribute.  If this does not
  //  match the actual size false will be returned.
  virtual bool GetExtendedFileAttribute(const base::FilePath& path,
                                        const std::string& name,
                                        char* value,
                                        ssize_t size);

  // Return true if the extended attribute |name| could be set with value
  // |value| on |path|.  Note that user namespace xattrs are not supported on
  // symlinks in linux and will return ENOTSUP if attempted.
  //
  // Parameters
  //  path - absolute file or directory path to set attributes for
  //  name - name including a namespace prefix. See getxattr(2)
  //  value - value to set for the extended attribute
  virtual bool SetExtendedFileAttribute(const base::FilePath& path,
                                        const std::string& name,
                                        const char* value,
                                        size_t size);

  // Return true if the extended attribute |name| could be removed on |path|.
  //
  // parameters
  //  path - absolute file or directory path to remove attributes from.
  //  name - name including a namespace prefix. See removexattr
  virtual bool RemoveExtendedFileAttribute(const base::FilePath& path,
                                           const std::string& name);

  // Return true if the ext file attributes for |name| could be succesfully set
  // in |flags|, possibly following symlink.
  //
  // Parameters
  //  path - absolute file or directory path to get attributes for
  //  flags - the pointer which will store the read flags
  virtual bool GetExtFileAttributes(const base::FilePath& path, int* flags);

  // Return true if the ext file attributes for |name| could be changed to
  // |flags|, possibly following symlink.
  //
  // Parameters
  //  path - absolute file or directory path to get attributes for
  //  flags - the value to update the ext attributes to
  virtual bool SetExtFileAttributes(const base::FilePath& path, int flags);

  // Return if ext file attributes associated with the |name| has FS_NODUMP_FL,
  // possibly following symlink.
  //
  // Parameters
  //  path - absolute file or directory path to look up
  virtual bool HasNoDumpFileAttribute(const base::FilePath& path);

  // Rename a file or directory
  //
  // Parameters
  //  from
  //  to
  virtual bool Rename(const base::FilePath& from, const base::FilePath& to);

  // Returns the current time.
  virtual base::Time GetCurrentTime() const;

  // Copies from to to.
  virtual bool Copy(const base::FilePath& from, const base::FilePath& to);

  // Calls statvfs() on path.
  //
  // Parameters
  //   path - path to statvfs on
  //   vfs - buffer to store result in
  virtual bool StatVFS(const base::FilePath& path, struct statvfs* vfs);

  // Check if the two paths are in the same vfs.
  //
  // Parameters
  //   mnt_a - first path.
  //   mnt_b - second path.
  virtual bool SameVFS(const base::FilePath& mnt_a,
                       const base::FilePath& mnt_b);

  // Find the device for a given filesystem.
  //
  // Parameters
  //   filesystem - the filesystem to examine
  //   device - output: the device name that "filesystem" in mounted on
  virtual bool FindFilesystemDevice(const base::FilePath& filesystem,
                                    std::string* device);

  // Runs "tune2fs -l" with redirected output.
  //
  // Parameters
  //  filesystem - the filesystem to examine
  //  lgofile - the path written with output
  virtual bool ReportFilesystemDetails(const base::FilePath& filesystem,
                                       const base::FilePath& logfile);

  // Sets up a process keyring which links to the user keyring and the session
  // keyring.
  virtual bool SetupProcessKeyring();

  // Gets the version of the dircrypto policy for the directory.
  virtual int GetDirectoryPolicyVersion(const base::FilePath& dir) const;

  // Returns true if kernel support fscrypt key ioctl (pre-req for v2 policy).
  virtual bool CheckFscryptKeyIoctlSupport() const;

  // Returns the state of the directory's encryption key.
  virtual dircrypto::KeyState GetDirCryptoKeyState(const base::FilePath& dir);

  // Sets up a directory to be encrypted with the provided key.
  virtual bool SetDirCryptoKey(const base::FilePath& dir,
                               const dircrypto::KeyReference& key_reference);

  // Invalidates the key to make dircrypto data inaccessible.
  virtual bool InvalidateDirCryptoKey(
      const dircrypto::KeyReference& key_reference,
      const base::FilePath& shadow_root);

  // Clears the kernel-managed user keyring
  virtual bool ClearUserKeyring();

  // Override the location of the mountinfo file used.
  // Default is kMountInfoFile.
  virtual void set_mount_info_path(const base::FilePath& mount_info_path) {
    mount_info_path_ = mount_info_path;
  }

  // Report condition of the Firmware Write-Protect flag.
  virtual bool FirmwareWriteProtected();

  // Syncs file data to disk for the given |path|. All metadata is synced as
  // well as file contents. This method is expensive and synchronous, use with
  // care.  Returns true on success.
  virtual bool SyncFile(const base::FilePath& path);

  // Calls fsync() on directory.  Returns true on success.
  //
  // Parameters
  //   path - Directory to be sync'ed
  virtual bool SyncDirectory(const base::FilePath& path);

  // Syncs everything to disk.  This method is synchronous and very, very
  // expensive; use with even more care than SyncFile.
  virtual void Sync();

  // Creates a new symbolic link at |path| pointing to |target|.  Returns false
  // if the link could not be created successfully.
  //
  // Parametesr
  //   path - The path to create the symbolic link at.
  //   target - The path that the symbolic link should point to.
  virtual bool CreateSymbolicLink(const base::FilePath& path,
                                  const base::FilePath& target);

  // Reads the target of a symbolic link at |path| into |target|.  If |path| is
  // not a symbolic link or the target cannot be read false is returned.
  //
  // Parameters
  //   path - The path of the symbolic link to read
  //   target - The path to fill with the symbolic link target.  If an error is
  //   encounted and false is returned, target will be cleared.
  virtual bool ReadLink(const base::FilePath& path, base::FilePath* target);

  // Sets the atime and mtime of a file to the provided values, optionally
  // following symlinks.
  //
  // Parameters
  //   path - The path of the file to set times for.  If this is a relative
  //   path, it is interpreted as relative to the current working directory of
  //   the calling process.
  //   atime - The time to set as the file's last access time.
  //   mtime - The time to set as the file's last modified time.
  //   follow_links - If set to true, symlinks will be dereferenced and their
  //   targets will be updated.
  virtual bool SetFileTimes(const base::FilePath& path,
                            const struct timespec& atime,
                            const struct timespec& mtime,
                            bool follow_links);

  // Copies |count| bytes of data from |from| to |to|, starting at |offset| in
  // |from| and the current file offset in |to|.  If
  // the copy fails or is only partially successful (bytes written does not
  // equal |count|) false is returned.
  //
  // Parameters
  //   fd_to - The file to copy data to.
  //   fd_from - The file to copy data from.
  //   offset - The location in |from| to begin copying data from.  This has no
  //   impact on the location in |to| that data is written to.
  //   count - The number of bytes to copy.
  virtual bool SendFile(int fd_to, int fd_from, off_t offset, size_t count);

  // Creates a sparse file.
  // Storage is only allocated when actually needed.
  // Empty sparse file doesn't use any space.
  // Returns true if the file is successfully created.
  //
  // Parameters
  //   path - The path to the file.
  //   size - The size to which sparse file should be resized.
  virtual bool CreateSparseFile(const base::FilePath& path, int64_t size);

  // Get the size of block device in bytes.
  //
  // Parameters
  //   device - path to the device.
  //   size (OUT) - size of the block device.
  virtual bool GetBlkSize(const base::FilePath& device, uint64_t* size);

  // DEPRECATED: do not use. Use LoopDeviceManager instead.
  // Detaches the loop device from associated file.
  // Doesn't delete the loop device itself.
  // Returns true if the loop device is successfully detached.
  //
  // Parameters
  //   device - Path to the loop device to be detached.
  virtual bool DetachLoop(const base::FilePath& device_path);

  // Discard device; call blkdiscard on the entire device.
  //
  // Parameters
  //   device - Device to call blkdiscard on.
  virtual bool DiscardDevice(const base::FilePath& device);

  // DEPRECATED: do not use. Use LoopDeviceManager instead.
  // Returns list of attached loop devices.
  virtual std::vector<LoopDevice> GetAttachedLoopDevices();

  // Formats the file or device into ext4 filesystem with default opts.
  // Returns true if formatting succeeded.
  //
  // Paratemers
  //   file - Path to the file or device to be formatted.
  //   opts - format opts.
  //   blocks - number of blocks.
  virtual bool FormatExt4(const base::FilePath& file,
                          const std::vector<std::string>& opts,
                          uint64_t blocks);

  // Tunes ext4 filesystem, adding features if needed.
  // Returns true if formatting succeeded.
  //
  // Paratemers
  //   file - Path to the file or device to be formatted.
  //   opts - format opts.
  virtual bool Tune2Fs(const base::FilePath& file,
                       const std::vector<std::string>& opts);

  // Resizes the file to blocks.
  // Returns true if resize succeeded.
  //
  // Parameters
  //   file - Path to the file to be resized.
  //   blocks - number of blocks to be resized to.
  virtual bool ResizeFilesystem(const base::FilePath& file, uint64_t blocks);

  // Returns the SELinux context of the file descriptor.
  // Returns nullopt in case of error.
  //
  // Parameters
  //   fd - The FD.
  virtual std::optional<std::string> GetSELinuxContextOfFD(int fd);

  // Set the SELinux context for the file/directory pointed by path.
  // Returns true if the context is set successfully.
  //
  // Parameters
  //   path - Path to set the SELinux context
  //   context - Name of the context that we want to set for path.
  virtual bool SetSELinuxContext(const base::FilePath& path,
                                 const std::string& context);

  // Restore SELinux file contexts. No-op if not compiled with -DUSE_SELINUX=1
  // Returns true if restorecon succeeded.
  //
  // Parameters
  //   path - Path to the file or directory to restore contexts.
  //   recursive - Whether to restore SELinux file contexts recursively.
  virtual bool RestoreSELinuxContexts(const base::FilePath& path,
                                      bool recursive);

  // Excludes certain paths from the following restorecon().
  //
  // Parameters
  //   exclude - Path to the files/directories that need to be excluded.
  virtual void AddGlobalSELinuxRestoreconExclusion(
      const std::vector<base::FilePath>& exclude);

  // Safely change a directory's mode.
  virtual bool SafeDirChmod(const base::FilePath& path, mode_t mode);

  // Safely change a directory's owner.
  virtual bool SafeDirChown(const base::FilePath& path,
                            uid_t user_id,
                            gid_t group_id);

  // This safely creates a directory and sets the permissions, looking for
  // symlinks and race conditions underneath.
  virtual bool SafeCreateDirAndSetOwnershipAndPermissions(
      const base::FilePath& path, mode_t mode, uid_t user_id, gid_t gid);

  // Calls "udevadm settle", optionally waiting for the device path to appear.
  virtual bool UdevAdmSettle(const base::FilePath& device_path,
                             bool wait_for_device);

  // Checks the header of the stateful partition for LVM metadata.
  virtual bool IsStatefulLogicalVolumeSupported();

  // Gets the block device for the underlying stateful partition.
  virtual base::FilePath GetStatefulDevice();

  virtual brillo::LoopDeviceManager* GetLoopDeviceManager();

  virtual brillo::LogicalVolumeManager* GetLogicalVolumeManager();

  // Creates a random unguessable token. The result is a non-null token.
  virtual base::UnguessableToken CreateUnguessableToken();

 private:
  // Calls fdatasync() on file if data_sync is true or fsync() on directory or
  // file when data_sync is false.  Returns true on success.
  //
  // Parameters
  //   path - File/directory to be sync'ed
  //   is_directory - True if |path| is a directory
  //   data_sync - True if |path| does not need metadata to be synced
  bool SyncFileOrDirectory(const base::FilePath& path,
                           bool is_directory,
                           bool data_sync);

  // Reads file at |path| into a blob-like object.
  // <T> needs to implement:
  // * .size()
  // * .resize()
  // * .data()
  // This function will attempt to verify a checksum for the file at |path|.
  template <class T>
  bool ReadFileToBlob(const base::FilePath& path, T* blob);

  // Computes a checksum and returns an ASCII representation.
  std::string GetChecksum(const void* input, size_t input_size);

  // Computes a checksum of |content| and writes it atomically to the same
  // |path| but with a .sum suffix and the given |mode|.
  void WriteChecksum(const base::FilePath& path,
                     const void* content,
                     size_t content_size,
                     mode_t mode);

  // Looks for a .sum file for |path| and verifies the checksum if it exists.
  void VerifyChecksum(const base::FilePath& path,
                      const void* content,
                      size_t content_size);

  // Returns list of mounts from |mount_info_path_| file.
  std::vector<DecodedProcMountInfo> ReadMountInfoFile();

  base::FilePath mount_info_path_;
  std::unique_ptr<brillo::LoopDeviceManager> loop_device_manager_;
  std::unique_ptr<brillo::LogicalVolumeManager> lvm_;
  std::unique_ptr<crossystem::Crossystem> crossystem_;

  friend class PlatformTest;
  FRIEND_TEST(PlatformTest, ReadMountInfoFileCorruptedMountInfo);
  FRIEND_TEST(PlatformTest, ReadMountInfoFileIncompleteMountInfo);
  FRIEND_TEST(PlatformTest, ReadMountInfoFileGood);
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_PLATFORM_H_
