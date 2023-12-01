// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VIRTUAL_FILE_PROVIDER_FUSE_MAIN_H_
#define VIRTUAL_FILE_PROVIDER_FUSE_MAIN_H_

#include <sys/types.h>

#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>

namespace virtual_file_provider {

// Delegate for FuseMain().
class FuseMainDelegate {
 public:
  virtual ~FuseMainDelegate() = default;

  // Returns the size of the file, or returns -1 if the ID is invalid.
  virtual int64_t GetSize(const std::string& id) = 0;

  // Handles a read request. Data should be written to the given FD.
  virtual void HandleReadRequest(const std::string& id,
                                 int64_t offset,
                                 int64_t size,
                                 base::ScopedFD fd) = 0;

  // FuseMain() calls this when an ID is released.
  virtual void NotifyIdReleased(const std::string& id) = 0;
};

// Mounts the FUSE file system on the given path and runs the FUSE main loop.
// This doesn't exit until the FUSE main loop exits (e.g. the file system is
// unmounted, or this process is terminated).
// Returns the value returned by libfuse's fuse_main().
int FuseMain(const base::FilePath& mount_path,
             FuseMainDelegate* delegate,
             std::optional<uid_t> userId,
             std::optional<gid_t> groupId);

}  // namespace virtual_file_provider

#endif  // VIRTUAL_FILE_PROVIDER_FUSE_MAIN_H_
