// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_PROCESS_ADAPTER_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_PROCESS_ADAPTER_H_

#include <string>
#include <vector>

#include <base/process/kill.h>
#include <base/process/process_handle.h>

namespace diagnostics {

// Provides an interface for controlling a single child process.
class DiagProcessAdapter {
 public:
  virtual ~DiagProcessAdapter() = default;

  // Retrieves the status of the child process.
  virtual base::TerminationStatus GetStatus(
      const base::ProcessHandle& handle) const = 0;

  // Launches the specified process.
  virtual bool StartProcess(const std::vector<std::string>& args,
                            base::ProcessHandle* handle) = 0;

  // Kills the process which was started earlier by StartProcess.
  virtual bool KillProcess(const base::ProcessHandle& handle) = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_PROCESS_ADAPTER_H_
