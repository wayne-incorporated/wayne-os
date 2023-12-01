// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_ASYNCHRONOUS_SIGNAL_HANDLER_H_
#define LIBBRILLO_BRILLO_ASYNCHRONOUS_SIGNAL_HANDLER_H_

#include <sys/signalfd.h>

#include <map>
#include <memory>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <brillo/asynchronous_signal_handler_interface.h>
#include <brillo/brillo_export.h>

namespace brillo {
// Sets up signal handlers for registered signals, and converts signal receipt
// into a write on a pipe. Watches that pipe for data and, when some appears,
// execute the associated callback.
class BRILLO_EXPORT AsynchronousSignalHandler final
    : public AsynchronousSignalHandlerInterface {
 public:
  using AsynchronousSignalHandlerInterface::SignalHandler;

  AsynchronousSignalHandler();
  ~AsynchronousSignalHandler() override;

  AsynchronousSignalHandler(const AsynchronousSignalHandler&) = delete;
  AsynchronousSignalHandler& operator=(const AsynchronousSignalHandler&) =
      delete;

  // Initialize the handler.
  void Init();

  // AsynchronousSignalHandlerInterface overrides.
  void RegisterHandler(int signal, const SignalHandler& callback) override;
  void UnregisterHandler(int signal) override;

 private:
  // Called from the main loop when we can read from |descriptor_|, indicated
  // that a signal was processed.
  void OnReadable();

  // Updates the set of signals that this handler listens to.
  BRILLO_PRIVATE void UpdateSignals();

  // Map from signal to its registered callback.
  using Callbacks = std::map<int, SignalHandler>;
  Callbacks registered_callbacks_;

  // File descriptor for accepting signals indicated by |signal_mask_|.
  base::ScopedFD descriptor_;

  // Controller used to manage watching of signalling pipe.
  std::unique_ptr<base::FileDescriptorWatcher::Controller> fd_watcher_;

  // A set of signals to be handled after the dispatcher is running.
  sigset_t signal_mask_;

  // A copy of the signal mask before the dispatcher starts, which will be
  // used to restore to the original state when the dispatcher stops.
  sigset_t saved_signal_mask_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_ASYNCHRONOUS_SIGNAL_HANDLER_H_
