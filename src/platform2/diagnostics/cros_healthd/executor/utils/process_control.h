// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_PROCESS_CONTROL_H_
#define DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_PROCESS_CONTROL_H_

#include <bits/types/siginfo_t.h>

#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback_forward.h>
#include <brillo/process/process_reaper.h>

#include "diagnostics/cros_healthd/executor/utils/sandboxed_process.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"

namespace diagnostics {

// Used for child process lifecycle control.
//
// This object holds a pointer of child process, and then this object will be
// added into a mojo::UniqueReceiverSet. So the routine in cros_healthd can use
// a mojo connection to control the lifecycle of this object, that is, the
// lifecycle of child process.
class ProcessControl : public ash::cros_healthd::mojom::ProcessControl {
 public:
  explicit ProcessControl(std::unique_ptr<SandboxedProcess> process,
                          brillo::ProcessReaper* process_reaper);
  ProcessControl(const ProcessControl&) = delete;
  ProcessControl& operator=(const ProcessControl&) = delete;
  ~ProcessControl() override;

  // Whether to redirect the stdout and stderr of the process into a memory
  // file.
  void RedirectOutputToMemory(bool combine_stdout_and_stderr);
  // Start the process and wait for it to end.
  void StartAndWait();

  // ash::cros_healthd::mojom::ProcessControl overrides
  void GetStdout(GetStdoutCallback callback) override;
  void GetStderr(GetStderrCallback callback) override;
  void GetReturnCode(GetReturnCodeCallback callback) override;
  void Kill() override;

 private:
  // Set the process as finished and run any pending callbacks.
  void SetProcessFinished(const siginfo_t& exit_status);

  // Helper function to cast a file descriptor into mojo::ScopedHandle.
  mojo::ScopedHandle GetMojoScopedHandle(int file_no);
  // The underlying process that is controlled by this object.
  std::unique_ptr<SandboxedProcess> process_;
  // Process Reaper is used to wait and get the return code of process.
  brillo::ProcessReaper* const process_reaper_;
  // The return code of the process.
  std::optional<int> return_code_;
  // Queue for storing pending callbacks before the process has finished
  // running.
  std::vector<GetReturnCodeCallback> get_return_code_callback_queue_;

  // Must be the last member of the class.
  base::WeakPtrFactory<ProcessControl> weak_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_PROCESS_CONTROL_H_
