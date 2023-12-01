// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM2_SIMULATOR_TPM_EXECUTOR_H_
#define TPM2_SIMULATOR_TPM_EXECUTOR_H_

#include <string>

namespace tpm2_simulator {

class TpmExecutor {
 public:
  TpmExecutor() = default;
  TpmExecutor(const TpmExecutor&) = delete;
  TpmExecutor& operator=(const TpmExecutor&) = delete;
  virtual ~TpmExecutor() = default;

  virtual void InitializeVTPM() = 0;
  virtual size_t GetCommandSize(const std::string& command) = 0;
  virtual std::string RunCommand(const std::string& command) = 0;
  virtual bool IsTPM2() = 0;
};

}  // namespace tpm2_simulator

#endif  // TPM2_SIMULATOR_TPM_EXECUTOR_H_
