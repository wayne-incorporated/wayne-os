// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_PROCESS_ADAPTER_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_PROCESS_ADAPTER_IMPL_H_

#include <string>
#include <vector>

#include "diagnostics/cros_healthd/routines/diag_process_adapter.h"

namespace diagnostics {

// Production implementation of DiagProcessAdapter.
class DiagProcessAdapterImpl final : public DiagProcessAdapter {
 public:
  DiagProcessAdapterImpl();
  DiagProcessAdapterImpl(const DiagProcessAdapterImpl&) = delete;
  DiagProcessAdapterImpl& operator=(const DiagProcessAdapterImpl&) = delete;
  ~DiagProcessAdapterImpl() override;
  base::TerminationStatus GetStatus(
      const base::ProcessHandle& handle) const override;
  bool StartProcess(const std::vector<std::string>& args,
                    base::ProcessHandle* handle) override;
  bool KillProcess(const base::ProcessHandle& handle) override;

 private:
  std::string exe_path_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_PROCESS_ADAPTER_IMPL_H_
