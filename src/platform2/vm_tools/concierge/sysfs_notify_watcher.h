// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_SYSFS_NOTIFY_WATCHER_H_
#define VM_TOOLS_CONCIERGE_SYSFS_NOTIFY_WATCHER_H_

#include <memory>

#include <base/functional/callback.h>

namespace vm_tools::concierge {

// Watch for high priority data (POLLPRI) on a file and run
// a specified callback when data is available

// Ideally base::FileDescriptorWatcher could be used, but POLLPRI is not
// currently supported by libchrome's message pump infrastructure. Once the
// switch from MessagePumpLibevent to MessagePumpEpoll in libchrome has been
// completed (crbug/1243354), POLLPRI support can be added to libchrome and we
// can switch to using a FileDescriptorWatcher instead.
class SysfsNotifyWatcher {
 public:
  using SysfsNotifyCallback = base::RepeatingCallback<void(const bool)>;

  static std::unique_ptr<SysfsNotifyWatcher> Create(
      int fd, const SysfsNotifyCallback& callback);

  virtual ~SysfsNotifyWatcher() = default;

  void SetCallback(const SysfsNotifyCallback& callback);

 protected:
  SysfsNotifyWatcher(int fd, const SysfsNotifyCallback& callback);

  virtual bool StartWatching() = 0;

  // The specific fd to watch
  int fd_;

  // The callback that is run after a POLLPRI event on fd
  SysfsNotifyCallback callback_;
};

}  // namespace vm_tools::concierge

#endif  // VM_TOOLS_CONCIERGE_SYSFS_NOTIFY_WATCHER_H_
