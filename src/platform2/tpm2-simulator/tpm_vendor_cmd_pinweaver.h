// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM2_SIMULATOR_TPM_VENDOR_CMD_PINWEAVER_H_
#define TPM2_SIMULATOR_TPM_VENDOR_CMD_PINWEAVER_H_

#include <string>

#include "tpm2-simulator/tpm_vendor_cmd.h"

namespace tpm2_simulator {

class TpmVendorCommandPinweaver : public TpmVendorCommand {
 public:
  TpmVendorCommandPinweaver() = default;
  TpmVendorCommandPinweaver(const TpmVendorCommandPinweaver&) = delete;
  TpmVendorCommandPinweaver& operator=(const TpmVendorCommandPinweaver&) =
      delete;
  virtual ~TpmVendorCommandPinweaver() = default;

  bool Init() override;
  bool IsVendorCommand(const std::string& command) override;
  std::string RunCommand(const std::string& command) override;
};

}  // namespace tpm2_simulator

#endif  // TPM2_SIMULATOR_TPM_VENDOR_CMD_PINWEAVER_H_
