// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TPM_SIMULATOR_HANDLE_H_
#define TRUNKS_TPM_SIMULATOR_HANDLE_H_

#include "trunks/command_transceiver.h"

#include <string>
#include <vector>

#include "trunks/error_codes.h"

namespace trunks {

// Sends command requests to an in-process software TPM. All commands are
// sent synchronously. The SendCommand method is supported but does not return
// until a response is received and the callback has been called. Command and
// response data are opaque to this class; it performs no validation.
//
// Example:
//   TpmSimulatorHandle handle;
//   if (!handle.Init()) {...}
//   std::string response = handle.SendCommandAndWait(command);
class TpmSimulatorHandle : public CommandTransceiver {
 public:
  explicit TpmSimulatorHandle(
      std::string simulator_state_directory = "/var/lib/trunks");
  TpmSimulatorHandle(const TpmSimulatorHandle&) = delete;
  TpmSimulatorHandle& operator=(const TpmSimulatorHandle&) = delete;

  ~TpmSimulatorHandle() override;

  // CommandTranceiver methods.
  bool Init() override;
  void SendCommand(const std::string& command,
                   ResponseCallback callback) override;
  std::string SendCommandAndWait(const std::string& command) override;

 private:
  // Initializes the simulator instance.
  void InitializeSimulator();

  bool init_ = false;
  std::string simulator_state_directory_;
};

}  // namespace trunks

#endif  // TRUNKS_TPM_SIMULATOR_HANDLE_H_
