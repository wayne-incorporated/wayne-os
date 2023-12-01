// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_SCOPED_MOUNT_NAMESPACE_H_
#define LIBBRILLO_BRILLO_SCOPED_MOUNT_NAMESPACE_H_

#include <memory>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>

#include <brillo/brillo_export.h>

namespace brillo {

// A class that restores a mount namespace when it goes out of scope. This can
// be done by entering another process' mount namespace by using
// CreateForPid(), or by supplying a mount namespace FD directly.
class BRILLO_EXPORT ScopedMountNamespace {
 public:
  // Enters the process identified by |pid|'s mount namespace and returns a
  // unique_ptr that restores the original mount namespace when it goes out of
  // scope.
  static std::unique_ptr<ScopedMountNamespace> CreateForPid(pid_t pid);

  // Enters the mount namespace identified by |path| and returns a unique_ptr
  // that restores the original mount namespace when it goes out of scope.
  static std::unique_ptr<ScopedMountNamespace> CreateFromPath(
      const base::FilePath& ns_path);

  explicit ScopedMountNamespace(base::ScopedFD mount_namespace_fd);
  ScopedMountNamespace(const ScopedMountNamespace&) = delete;
  ScopedMountNamespace& operator=(const ScopedMountNamespace&) = delete;

  ~ScopedMountNamespace();

 private:
  base::ScopedFD mount_namespace_fd_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_SCOPED_MOUNT_NAMESPACE_H_
