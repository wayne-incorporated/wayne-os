// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_PLATFORM_H_
#define CROS_DISKS_PLATFORM_H_

#include <string>
#include <unordered_set>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <chromeos/dbus/service_constants.h>

#include "cros-disks/metrics.h"

namespace cros_disks {

// A class that provides functionalities such as creating and removing
// directories, and getting user ID and group ID for a username.
class Platform {
 public:
  explicit Platform(Metrics* metrics = nullptr);
  Platform(const Platform&) = delete;
  Platform& operator=(const Platform&) = delete;

  virtual ~Platform() = default;

  // Gets the canonicalized absolute path of |path| using realpath() and returns
  // that via |real_path|. Return true on success.
  virtual bool GetRealPath(const std::string& path,
                           std::string* real_path) const;

  // Returns whether |path| exists.
  virtual bool PathExists(const std::string& path) const;

  // Returns whether |path| exists and is a directory.
  virtual bool DirectoryExists(const std::string& path) const;

  // lstats the |path|.
  virtual bool Lstat(const std::string& path, base::stat_wrapper_t* out) const;

  // Creates a directory at |path| if it does not exist. Returns true on
  // success.
  virtual bool CreateDirectory(const std::string& path) const;

  // Creates a directory at |path| if it does not exist. If |path| already
  // exists and is a directory, this function tries to reuse it if it is empty
  // not in use. The created directory is only accessible by the current user.
  // Returns true if the directory is created successfully.
  virtual bool CreateOrReuseEmptyDirectory(const std::string& path) const;

  // Creates a directory at |path| similar to CreateOrReuseEmptyDirectory()
  // but avoids using any paths in the |reserved_paths| set and retries on
  // failure by augmenting a numeric suffix (e.g. "mydir (1)"), starting from
  // 1 to |max_suffix_to_retry|, to the directory name. The created directory
  // is only accessible by the current user. Returns true if the directory is
  // created successfully.
  virtual bool CreateOrReuseEmptyDirectoryWithFallback(
      std::string* path,
      unsigned max_suffix_to_retry,
      const std::unordered_set<std::string>& reserved_paths) const;

  // Creates a temporary directory inside |dir| and sets its path to |path|.
  virtual bool CreateTemporaryDirInDir(const std::string& dir,
                                       const std::string& prefix,
                                       std::string* path) const;

  // Writes contents of the |data| to a file. Returns the number of bytes
  // written, or -1 on error.
  virtual int WriteFile(const std::string& file,
                        const char* data,
                        int size) const;

  // Reads at most |size| bytes from the |file| to a buffer |data| and returns
  // number of bytes actually read, or -1 on error.
  virtual int ReadFile(const std::string& file, char* data, int size) const;

  // Returns the fallback directory name of |path| using |suffix| as follows:
  //   "|path| (|suffix|)" if |path| ends with a ASCII digit, or
  //   "|path| |suffix|" otherwise.
  std::string GetDirectoryFallbackName(const std::string& path,
                                       unsigned suffix) const;

  // Gets the group ID of a given group name. Returns true on success.
  virtual bool GetGroupId(const std::string& group_name, gid_t* group_id) const;

  // Gets the user ID and group ID of a given user name. Returns true on
  // success.
  virtual bool GetUserAndGroupId(const std::string& user_name,
                                 uid_t* user_id,
                                 gid_t* group_id) const;

  // Gets the user ID and group ID of |path|. If |path| is a symbolic link, the
  // ownership of the linked file, not the symbolic link itself, is obtained.
  // Returns true on success.
  virtual bool GetOwnership(const std::string& path,
                            uid_t* user_id,
                            gid_t* group_id) const;

  // Gets the permissions of |path|. If |path| is a symbolic link, the
  // permissions of the linked file, not the symbolic link itself, is obtained.
  // Returns true on success.
  virtual bool GetPermissions(const std::string& path, mode_t* mode) const;

  // Removes a directory at |path| if it is empty and not in use. Returns true
  // on success, or if the directory does not exist in the first place.
  virtual bool RemoveEmptyDirectory(const std::string& path) const;

  // Makes |user_name| to perform mount operations, which changes the value of
  // mount_group_id_ and mount_user_id_. When |user_name| is a non-root user, a
  // mount operation respecting the value of mount_group_id_ and mount_user_id_
  // becomes non-privileged. Returns false if it fails to obtain the user and
  // group ID of |user_name|.
  bool SetMountUser(const std::string& user_name);

  // Sets the user ID and group ID of |path| to |user_id| and |group_id|,
  // respectively. Returns true on success.
  virtual bool SetOwnership(const std::string& path,
                            uid_t user_id,
                            gid_t group_id) const;

  // Sets the permissions of |path| to |mode|. Returns true on success.
  virtual bool SetPermissions(const std::string& path, mode_t mode) const;

  // Forcefully unmounts |mount_path|. The given |filesystem_type| is only used
  // in logs.
  virtual MountError Unmount(const base::FilePath& mount_path,
                             const std::string& filesystem_type) const;

  // Mounts the |source| filesystem of type |filesystem_type| at mount point
  // |target| with |flags| and |options|.
  virtual MountError Mount(const std::string& source,
                           const std::string& target,
                           const std::string& filesystem_type,
                           uint64_t flags,
                           const std::string& options) const;

  // Unmounts and removes all the subdirectories of |dir|.
  virtual bool CleanUpStaleMountPoints(const std::string& dir) const;

  gid_t mount_group_id() const { return mount_group_id_; }

  uid_t mount_user_id() const { return mount_user_id_; }

  const std::string& mount_user() const { return mount_user_; }

 private:
  // Optional pointer to an object that can record UMA histograms.
  Metrics* const metrics_;

  // Group ID to perform mount operations.
  gid_t mount_group_id_ = 0;

  // User ID to perform mount operations.
  uid_t mount_user_id_ = 0;

  // User ID to perform mount operations.
  std::string mount_user_ = "root";
};

}  // namespace cros_disks

#endif  // CROS_DISKS_PLATFORM_H_
