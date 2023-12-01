// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_SYSFS_NOTIFY_WATCHER_IMPL_H_
#define VM_TOOLS_CONCIERGE_SYSFS_NOTIFY_WATCHER_IMPL_H_

#include <base/task/sequenced_task_runner.h>
#include <base/threading/thread.h>

#include "vm_tools/concierge/sysfs_notify_watcher.h"

namespace vm_tools::concierge {

// Watch for high priority data (POLLPRI) on a file and run
// a specified callback when data is available
// Note: This class reports POLLPRI events with a 'best effort' approach. Not
// all events are guaranteed to be reported, especially if they occur in rapid
// succession.

// Ideally base::FileDescriptorWatcher could be used, but POLLPRI is not
// currently supported by libchrome's message pump infrastructure. Once the
// switch from MessagePumpLibevent to MessagePumpEpoll in libchrome has been
// completed (crbug/1243354), POLLPRI support can be added to libchrome and we
// can switch to using a FileDescriptorWatcher instead.
class SysfsNotifyWatcherImpl final : public SysfsNotifyWatcher {
 public:
  SysfsNotifyWatcherImpl(int fd, const SysfsNotifyCallback& callback);

 protected:
  // Start watching the fd.
  // SysfsNotifyWatcher overrides.
  bool StartWatching() override;

 private:
  // Callback that runs when poll() returns.
  void PollEvent(bool success);

  // Polls once on the watched fd.
  // Runs on poll_thread_.
  void PollOnThread(int fd);

  // Used to run a poll() in the background.
  base::Thread poll_thread_{"Sysfs Notify Poll Thread"};

  // Runs tasks on the sequence on which this was instantiated (the
  // sequence on which the callback must run).
  const scoped_refptr<base::SequencedTaskRunner> main_thread_task_runner_ =
      base::SequencedTaskRunner::GetCurrentDefault();
};

}  // namespace vm_tools::concierge

#endif  // VM_TOOLS_CONCIERGE_SYSFS_NOTIFY_WATCHER_IMPL_H_
