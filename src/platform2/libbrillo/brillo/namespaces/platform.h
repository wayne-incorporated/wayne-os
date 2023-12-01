// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_NAMESPACES_PLATFORM_H_
#define LIBBRILLO_BRILLO_NAMESPACES_PLATFORM_H_

#include <sys/types.h>

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

namespace brillo {
// Platform specific routines abstraction layer.
// Also helps us to be able to mock them in tests.
class BRILLO_EXPORT Platform {
 public:
  Platform();
  Platform(const Platform&) = delete;
  Platform& operator=(const Platform&) = delete;

  virtual ~Platform();
  // Calls the platform fork() function and returns the pid returned
  // by fork().
  virtual pid_t Fork();

  // Calls the platform unmount.
  //
  // Parameters
  //   path - The path to unmount
  //   lazy - Whether to call a lazy unmount
  //   was_busy (OUT) - Set to true on return if the mount point was busy
  virtual bool Unmount(const base::FilePath& path, bool lazy, bool* was_busy);

  // Calls the platform mount.
  //
  // Parameters
  //   source - The path to mount from
  //   target - The path to mount to
  //   fs_type - File system type of the mount
  //   mount_flags - Flags spesifying the type of the mount operation
  //   data - Mount options
  virtual int Mount(const std::string& source,
                    const std::string& target,
                    const std::string& fs_type,
                    uint64_t mount_flags,
                    const void* = nullptr);

  // Checks the file system type of the |path| and returns true if the
  // filesystem type is nsfs.
  //
  // Parameters
  //   path - The path to check the file system type
  virtual bool FileSystemIsNsfs(const base::FilePath& path);

  // Calls the platform waitpid() function and returns the value returned by
  // waitpid().
  //
  // Parameters
  //   pid - The child pid to be waited on
  //   status (OUT)- Termination status of a child process.
  virtual pid_t Waitpid(pid_t pid, int* status);
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_NAMESPACES_PLATFORM_H_
