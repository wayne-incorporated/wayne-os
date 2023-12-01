// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TPM_HANDLE_H_
#define TRUNKS_TPM_HANDLE_H_

#include "trunks/command_transceiver.h"

#include <string>

#include "trunks/error_codes.h"
#include "trunks/resilience/write_error_tracker.h"
#include "trunks/trunks_metrics.h"

namespace trunks {

// Sends commands to a TPM device via a handle to /dev/tpm0. All commands are
// sent synchronously. The SendCommand method is supported but does not return
// until a response is received and the callback has been called. Command and
// response data are opaque to this class; it performs no validation.
//
// Example:
//   TpmHandle handle;
//   if (!handle.Init()) {...}
//   std::string response = handle.SendCommandAndWait(command);
class TpmHandle : public CommandTransceiver {
 public:
  explicit TpmHandle(WriteErrorTracker& write_error_tracker);
  TpmHandle(const TpmHandle&) = delete;
  TpmHandle& operator=(const TpmHandle&) = delete;

  ~TpmHandle() override;

  // Initializes a TpmHandle instance. This method must be called successfully
  // before any other method. Returns true on success.
  bool Init() override;

  // CommandTranceiver methods.
  void SendCommand(const std::string& command,
                   ResponseCallback callback) override;
  std::string SendCommandAndWait(const std::string& command) override;

 private:
  // Writes a |command| to /dev/tpm0 and reads the |response|. Returns
  // TPM_RC_SUCCESS on success.
  TPM_RC SendCommandInternal(const std::string& command, std::string* response);

  int fd_;  // A file descriptor for /dev/tpm0.
  // A TrunksMetrics instance for report UMA
  TrunksMetrics metrics_;
  WriteErrorTracker& write_error_tracker_;
};

}  // namespace trunks

#endif  // TRUNKS_TPM_HANDLE_H_
