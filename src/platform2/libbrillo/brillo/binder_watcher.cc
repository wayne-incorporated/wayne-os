// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/binder_watcher.h>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>

using android::IPCThreadState;
using android::ProcessState;

namespace {
// Called from the message loop whenever the binder file descriptor is ready.
void OnBinderReadReady() {
  IPCThreadState::self()->handlePolledCommands();
}
}  // namespace

namespace brillo {

BinderWatcher::BinderWatcher() = default;

BinderWatcher::~BinderWatcher() = default;

bool BinderWatcher::Init() {
  int binder_fd = -1;
  ProcessState::self()->setThreadPoolMaxThreadCount(0);
  IPCThreadState::self()->disableBackgroundScheduling(true);
  int err = IPCThreadState::self()->setupPolling(&binder_fd);
  if (err != 0) {
    LOG(ERROR) << "Error setting up binder polling: "
               << logging::SystemErrorCodeToString(err);
    return false;
  }
  if (binder_fd < 0) {
    LOG(ERROR) << "Invalid binder FD " << binder_fd;
    return false;
  }
  VLOG(1) << "Got binder FD " << binder_fd;

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      binder_fd, base::BindRepeating(&OnBinderReadReady));
  if (!watcher_) {
    LOG(ERROR) << "Failed to watch binder FD";
    return false;
  }
  return true;
}

}  // namespace brillo
