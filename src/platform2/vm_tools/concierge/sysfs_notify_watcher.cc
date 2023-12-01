// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/sysfs_notify_watcher.h"

#include <memory>

#include "vm_tools/concierge/sysfs_notify_watcher_impl.h"

namespace vm_tools::concierge {

std::unique_ptr<SysfsNotifyWatcher> SysfsNotifyWatcher::Create(
    int fd, const SysfsNotifyCallback& callback) {
  std::unique_ptr<SysfsNotifyWatcher> watcher =
      std::unique_ptr<SysfsNotifyWatcherImpl>(
          new SysfsNotifyWatcherImpl(fd, callback));

  if (!watcher->StartWatching()) {
    return {};
  }

  return watcher;
}

SysfsNotifyWatcher::SysfsNotifyWatcher(int fd,
                                       const SysfsNotifyCallback& callback)
    : fd_(fd), callback_(callback) {}

void SysfsNotifyWatcher::SetCallback(const SysfsNotifyCallback& callback) {
  callback_ = callback;
}

}  // namespace vm_tools::concierge
