// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM2_SIMULATOR_TPM_VENDOR_CMD_LOCALITY_H_
#define TPM2_SIMULATOR_TPM_VENDOR_CMD_LOCALITY_H_

#include <string>

#include "tpm2-simulator/tpm_vendor_cmd.h"

namespace tpm2_simulator {

class TpmVendorCommandLocality : public TpmVendorCommand {
 public:
  TpmVendorCommandLocality() = default;
  TpmVendorCommandLocality(const TpmVendorCommandLocality&) = delete;
  TpmVendorCommandLocality& operator=(const TpmVendorCommandLocality&) = delete;
  virtual ~TpmVendorCommandLocality() = default;

  bool Init() override;
  bool IsVendorCommand(const std::string& command) override;
  std::string RunCommand(const std::string& command) override;
};

}  // namespace tpm2_simulator

#endif  // TPM2_SIMULATOR_TPM_VENDOR_CMD_LOCALITY_H_
