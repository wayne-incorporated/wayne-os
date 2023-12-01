// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/sysfs_notify_watcher_impl.h"

#include <poll.h>
#include <unistd.h>

#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>

// TODO(b:254164308) remove this once vm_sockets.h is updated to kernel >=5.6
// version
#define VMADDR_CID_LOCAL 1

namespace vm_tools::concierge {

SysfsNotifyWatcherImpl::SysfsNotifyWatcherImpl(
    int fd, const SysfsNotifyCallback& callback)
    : SysfsNotifyWatcher(fd, callback) {}

bool SysfsNotifyWatcherImpl::StartWatching() {
  // Since poll is a blocking call spawn a separate thread that will perform the
  // poll and wait until it returns. The poll event will be sent to the main
  // thread when it happens.
  if (!poll_thread_.StartWithOptions(base::Thread::Options(
          base::MessagePumpType::IO,
          0 /* stack_size: 0 corresponds to the default size*/))) {
    LOG(ERROR) << "Failed to start sysfs notify watch thread";
    return false;
  }

  // poll() on the fd on the polling thread.
  // Safety note: Unretained(this) is safe since the poll_thread_ lifetime is
  // coupled to the lifetime of this instance.
  poll_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&SysfsNotifyWatcherImpl::PollOnThread,
                                base::Unretained(this), fd_));

  return true;
}

void SysfsNotifyWatcherImpl::PollOnThread(int fd) {
  struct pollfd p;
  p.fd = fd;
  p.events = POLLPRI;
  p.revents = 0;

  // Blocking call. This will only return once POLLPRI is set on the fd or an
  // error occurs.
  int ret = HANDLE_EINTR(poll(&p, 1, -1));

  // Report the poll result to the main thread.
  // Safety note: Unretained(this) is safe since the poll_thread_ lifetime
  // (where this function is run) is coupled to the lifetime of this instance.
  main_thread_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&SysfsNotifyWatcherImpl::PollEvent,
                                base::Unretained(this), ret > 0));
}

void SysfsNotifyWatcherImpl::PollEvent(bool success) {
  callback_.Run(success);

  // After a poll event, poll again
  // Safety note: Unretained(this) is safe since the poll_thread_ lifetime is
  // coupled to the lifetime of this instance.
  poll_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&SysfsNotifyWatcherImpl::PollOnThread,
                                base::Unretained(this), fd_));
}

}  // namespace vm_tools::concierge
