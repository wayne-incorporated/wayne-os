// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/asynchronous_signal_handler.h"

#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>

namespace brillo {

AsynchronousSignalHandler::AsynchronousSignalHandler() {
  CHECK_EQ(sigemptyset(&signal_mask_), 0) << "Failed to initialize signal mask";
  CHECK_EQ(sigemptyset(&saved_signal_mask_), 0)
      << "Failed to initialize signal mask";
}

AsynchronousSignalHandler::~AsynchronousSignalHandler() {
  fd_watcher_ = nullptr;

  if (!descriptor_.is_valid())
    return;

  // Close FD before restoring sigprocmask.
  descriptor_.reset();
  CHECK_EQ(0, sigprocmask(SIG_SETMASK, &saved_signal_mask_, nullptr));
}

void AsynchronousSignalHandler::Init() {
  // Making sure it is not yet initialized.
  CHECK(!descriptor_.is_valid());

  // Set sigprocmask before creating signalfd.
  CHECK_EQ(0, sigprocmask(SIG_BLOCK, &signal_mask_, &saved_signal_mask_));

  // Creating signalfd, and start watching it.
  descriptor_.reset(signalfd(-1, &signal_mask_, SFD_CLOEXEC | SFD_NONBLOCK));
  CHECK(descriptor_.is_valid());
  fd_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      descriptor_.get(),
      base::BindRepeating(&AsynchronousSignalHandler::OnReadable,
                          base::Unretained(this)));
  CHECK(fd_watcher_) << "Watching signalfd failed.";
}

void AsynchronousSignalHandler::RegisterHandler(int signal,
                                                const SignalHandler& callback) {
  registered_callbacks_[signal] = callback;
  CHECK_EQ(0, sigaddset(&signal_mask_, signal));
  UpdateSignals();
}

void AsynchronousSignalHandler::UnregisterHandler(int signal) {
  Callbacks::iterator callback_it = registered_callbacks_.find(signal);
  if (callback_it == registered_callbacks_.end())
    return;
  registered_callbacks_.erase(callback_it);
  CHECK_EQ(0, sigdelset(&signal_mask_, signal));
  UpdateSignals();
}

void AsynchronousSignalHandler::OnReadable() {
  struct signalfd_siginfo info;
  while (base::ReadFromFD(descriptor_.get(), reinterpret_cast<char*>(&info),
                          sizeof(info))) {
    int signal = info.ssi_signo;
    Callbacks::iterator callback_it = registered_callbacks_.find(signal);
    if (callback_it == registered_callbacks_.end()) {
      LOG(WARNING) << "Unable to find a signal handler for signal: " << signal;
      // Can happen if a signal has been called multiple time, and the callback
      // asked to be unregistered the first time.
      continue;
    }
    const SignalHandler& callback = callback_it->second;
    bool must_unregister = callback.Run(info);
    if (must_unregister)
      UnregisterHandler(signal);
  }
}

void AsynchronousSignalHandler::UpdateSignals() {
  if (!descriptor_.is_valid())
    return;
  sigset_t mask;
  CHECK_EQ(0, sigemptyset(&mask));
  CHECK_EQ(0, sigorset(&mask, &signal_mask_, &saved_signal_mask_));
  CHECK_EQ(0, sigprocmask(SIG_SETMASK, &mask, nullptr));
  CHECK_EQ(descriptor_.get(), signalfd(descriptor_.get(), &signal_mask_,
                                       SFD_CLOEXEC | SFD_NONBLOCK));
}

}  // namespace brillo
