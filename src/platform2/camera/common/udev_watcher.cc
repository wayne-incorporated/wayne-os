/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "cros-camera/udev_watcher.h"

#include <string>
#include <utility>

#include <libudev.h>

#include <base/check.h>
#include <base/notreached.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/thread.h>

#include "cros-camera/common.h"
#include "cros-camera/future.h"

namespace cros {

UdevWatcher::Observer::~Observer() = default;

void UdevWatcher::Observer::OnDeviceAdded(ScopedUdevDevicePtr /*device*/) {}

void UdevWatcher::Observer::OnDeviceRemoved(ScopedUdevDevicePtr /*device*/) {}

UdevWatcher::UdevWatcher(Observer* observer, std::string subsystem)
    : observer_(observer),
      subsystem_(std::move(subsystem)),
      thread_("UdevWatcherThread") {}

UdevWatcher::~UdevWatcher() {
  if (!thread_.IsRunning()) {
    // No-op destructor if the watcher thread is not running. It could happen
    // if Start() failed or is not getting called at all.
    return;
  }
  // Post a task to reset FileDescriptorWatcher and explicitly call
  // Thread::Stop() to ensure it is completed before destroying fields.
  thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&UdevWatcher::StopOnThread, base::Unretained(this)));
  thread_.Stop();
}

bool UdevWatcher::Start(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  udev_.reset(udev_new());
  if (!udev_) {
    LOGF(ERROR) << "udev_new failed";
    return false;
  }

  mon_.reset(udev_monitor_new_from_netlink(udev_.get(), "udev"));
  if (!mon_) {
    LOGF(ERROR) << "udev_monitor_new_from_netlink failed";
    return false;
  }

  if (udev_monitor_filter_add_match_subsystem_devtype(
          mon_.get(), subsystem_.c_str(), nullptr) < 0) {
    LOGF(ERROR) << "udev_monitor_filter_add_match_subsystem_devtype failed";
    return false;
  }

  if (udev_monitor_enable_receiving(mon_.get()) < 0) {
    LOGF(ERROR) << "udev_monitor_enable_receiving failed";
    return false;
  }

  int fd = udev_monitor_get_fd(mon_.get());
  if (fd < 0) {
    LOGF(ERROR) << "udev_monitor_get_fd failed";
    return false;
  }

  if (!thread_.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOGF(ERROR) << "thread start failed";
    return false;
  }

  callback_task_runner_ = task_runner;

  auto future = cros::Future<bool>::Create(nullptr);
  thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&UdevWatcher::StartOnThread, base::Unretained(this), fd,
                     cros::GetFutureCallback(future)));
  return future->Get();
}

bool UdevWatcher::EnumerateExistingDevices() {
  DCHECK(callback_task_runner_) << "Start() shuold be called first";
  DCHECK(callback_task_runner_->BelongsToCurrentThread());

  ScopedUdevEnumeratePtr enumerate(udev_enumerate_new(udev_.get()));
  if (!enumerate) {
    LOGF(ERROR) << "udev_enumerate_new failed";
    return false;
  }

  if (udev_enumerate_add_match_subsystem(enumerate.get(), subsystem_.c_str()) <
      0) {
    LOGF(ERROR) << "udev_enumerate_add_match_subsystem failed";
    return false;
  }

  if (udev_enumerate_scan_devices(enumerate.get()) < 0) {
    LOGF(ERROR) << "udev_enumerate_scan_devices failed";
    return false;
  }

  for (udev_list_entry* entry = udev_enumerate_get_list_entry(enumerate.get());
       entry != nullptr; entry = udev_list_entry_get_next(entry)) {
    // We simply ignore errors in some entries here, and keep enumerating.

    const char* name = udev_list_entry_get_name(entry);
    if (!name) {
      LOGF(WARNING) << "udev_list_entry_get_name failed";
      continue;
    }

    ScopedUdevDevicePtr dev(udev_device_new_from_syspath(udev_.get(), name));
    if (!dev) {
      LOGF(WARNING) << "udev_device_new_from_syspath failed";
      continue;
    }

    observer_->OnDeviceAdded(std::move(dev));
  }

  return true;
}

void UdevWatcher::StartOnThread(int fd,
                                base::OnceCallback<void(bool)> callback) {
  DCHECK(thread_.task_runner()->BelongsToCurrentThread());

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd,
      base::BindRepeating(&UdevWatcher::OnReadable, base::Unretained(this)));
  if (!watcher_) {
    LOGF(ERROR) << "Failed to start watching a file descriptor";
    std::move(callback).Run(false);
    return;
  }

  std::move(callback).Run(true);
}

void UdevWatcher::StopOnThread() {
  watcher_ = nullptr;
}

void UdevWatcher::OnReadable() {
  DCHECK(thread_.task_runner()->BelongsToCurrentThread());

  ScopedUdevDevicePtr dev(udev_monitor_receive_device(mon_.get()));
  if (!dev) {
    LOGF(ERROR) << "udev_monitor_receive_device failed";
    return;
  }

  const char* action = udev_device_get_action(dev.get());
  if (!action) {
    LOGF(ERROR) << "udev_device_get_action failed";
    return;
  }

  decltype(&Observer::OnDeviceAdded) callback;
  if (strcmp(action, "add") == 0) {
    callback = &Observer::OnDeviceAdded;
  } else if (strcmp(action, "remove") == 0) {
    callback = &Observer::OnDeviceRemoved;
  } else {
    NOTREACHED() << "Unexpected action " << action;
    return;
  }

  callback_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(callback, base::Unretained(observer_), std::move(dev)));
}

}  // namespace cros
