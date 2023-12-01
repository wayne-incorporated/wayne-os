// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM2_SIMULATOR_TPM_EXECUTOR_TI50_IMPL_H_
#define TPM2_SIMULATOR_TPM_EXECUTOR_TI50_IMPL_H_

#include <memory>
#include <string>
#include <vector>

#include <brillo/process/process.h>

#include "tpm2-simulator/export.h"
#include "tpm2-simulator/tpm_executor.h"
#include "tpm2-simulator/tpm_vendor_cmd.h"

namespace tpm2_simulator {

class TPM2_SIMULATOR_EXPORT TpmExecutorTi50Impl : public TpmExecutor {
 public:
  TpmExecutorTi50Impl();
  TpmExecutorTi50Impl(const TpmExecutorTi50Impl&) = delete;
  TpmExecutorTi50Impl& operator=(const TpmExecutorTi50Impl&) = delete;
  virtual ~TpmExecutorTi50Impl();

  void InitializeVTPM() override;
  size_t GetCommandSize(const std::string& command) override;
  std::string RunCommand(const std::string& command) override;
  bool IsTPM2() override { return true; }

 private:
  std::vector<std::unique_ptr<TpmVendorCommand>> vendor_commands_;
  brillo::ProcessImpl process_;
};

}  // namespace tpm2_simulator

#endif  // TPM2_SIMULATOR_TPM_EXECUTOR_TI50_IMPL_H_
