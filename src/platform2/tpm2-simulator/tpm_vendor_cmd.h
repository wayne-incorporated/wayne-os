// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM2_SIMULATOR_TPM_VENDOR_CMD_H_
#define TPM2_SIMULATOR_TPM_VENDOR_CMD_H_

#include <string>

namespace tpm2_simulator {

class TpmVendorCommand {
 public:
  TpmVendorCommand() = default;
  TpmVendorCommand(const TpmVendorCommand&) = delete;
  TpmVendorCommand& operator=(const TpmVendorCommand&) = delete;
  virtual ~TpmVendorCommand() = default;

  virtual bool Init() = 0;
  virtual bool IsVendorCommand(const std::string& command) = 0;
  virtual std::string RunCommand(const std::string& command) = 0;
};

}  // namespace tpm2_simulator

#endif  // TPM2_SIMULATOR_TPM_VENDOR_CMD_H_
