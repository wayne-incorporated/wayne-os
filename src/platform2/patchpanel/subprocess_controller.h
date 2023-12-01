// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_SUBPROCESS_CONTROLLER_H_
#define PATCHPANEL_SUBPROCESS_CONTROLLER_H_

#include <sys/types.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>

#include "patchpanel/ipc.h"
#include "patchpanel/message_dispatcher.h"

namespace shill {
class ProcessManager;
}  // namespace shill

namespace patchpanel {

class System;

// Tracks a helper subprocess.  Handles forking, cleaning up on termination,
// and IPC.
// This object is used by the main Manager process.
class SubprocessController {
 public:
  // The caller should guarantee the |system| and |process_manager| outlive
  // the SubprocessController instance.
  SubprocessController(System* system,
                       shill::ProcessManager* process_manager,
                       const base::FilePath& cmd_path,
                       const std::string& fd_arg);
  SubprocessController(const SubprocessController&) = delete;
  SubprocessController& operator=(const SubprocessController&) = delete;

  virtual ~SubprocessController();

  // Re-execs patchpanel with a new argument: |argv_| + "|fd_arg_|=N", where N
  // is the side of |control_fd|. This tells the subprocess to start up a
  // different mainloop.
  void Start();

  // Serializes a protobuf and sends it to the helper process.
  void SendControlMessage(const ControlMessage& proto) const;

  // Starts listening on messages from subprocess and dispatching them to
  // handlers. This function can only be called after that the message loop of
  // main process is initialized.
  void Listen();

  void RegisterFeedbackMessageHandler(
      base::RepeatingCallback<void(const FeedbackMessage&)> handler);

 private:
  // The callback that is called when the subprocess is exited unexpectedly.
  // Attempts to restart the subprocess with exponential backoff delay.
  void OnProcessExitedUnexpectedly(int exit_status);
  void OnMessage(const SubprocessMessage& msg);

  base::RepeatingCallback<void(const FeedbackMessage&)> feedback_handler_;

  // Used to create the subprocess and watch the subprocess exited unexpectedly.
  System* system_;
  // The singleton instance which is used to create the subprocess and watch the
  // subprocess exited unexpectedly.
  shill::ProcessManager* process_manager_;

  std::optional<pid_t> pid_ = std::nullopt;
  uint8_t restarts_{0};
  base::FilePath cmd_path_;
  std::vector<std::string> argv_;
  std::string fd_arg_;
  std::unique_ptr<MessageDispatcher<SubprocessMessage>> msg_dispatcher_;

  base::WeakPtrFactory<SubprocessController> weak_factory_{this};
};

}  // namespace patchpanel

#endif  // PATCHPANEL_SUBPROCESS_CONTROLLER_H_
