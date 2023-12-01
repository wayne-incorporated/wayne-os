// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/scoped_mount_namespace.h"

#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>
#include <utility>

#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/stringprintf.h>

namespace {
constexpr char kCurrentMountNamespacePath[] = "/proc/self/ns/mnt";
}  // anonymous namespace

namespace brillo {

ScopedMountNamespace::ScopedMountNamespace(base::ScopedFD mount_namespace_fd)
    : mount_namespace_fd_(std::move(mount_namespace_fd)) {}

ScopedMountNamespace::~ScopedMountNamespace() {
  PLOG_IF(ERROR, setns(mount_namespace_fd_.get(), CLONE_NEWNS) != 0)
      << "Ignoring failure to restore original mount namespace";
}

// static
std::unique_ptr<ScopedMountNamespace> ScopedMountNamespace::CreateForPid(
    pid_t pid) {
  std::string ns_path = base::StringPrintf("/proc/%d/ns/mnt", pid);
  return CreateFromPath(base::FilePath(ns_path));
}

// static
std::unique_ptr<ScopedMountNamespace> ScopedMountNamespace::CreateFromPath(
    const base::FilePath& ns_path) {
  base::ScopedFD original_mount_namespace_fd(
      HANDLE_EINTR(open(kCurrentMountNamespacePath, O_RDONLY)));
  if (!original_mount_namespace_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open original mount namespace FD at "
                << kCurrentMountNamespacePath;
    return nullptr;
  }

  base::ScopedFD mount_namespace_fd(
      HANDLE_EINTR(open(ns_path.value().c_str(), O_RDONLY)));
  if (!mount_namespace_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open mount namespace FD at " << ns_path.value();
    return nullptr;
  }

  if (setns(mount_namespace_fd.get(), CLONE_NEWNS) != 0) {
    PLOG(ERROR) << "Failed to enter mount namespace at " << ns_path.value();
    return nullptr;
  }

  return std::make_unique<ScopedMountNamespace>(
      std::move(original_mount_namespace_fd));
}

}  // namespace brillo
