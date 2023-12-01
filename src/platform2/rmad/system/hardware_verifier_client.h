// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_HARDWARE_VERIFIER_CLIENT_H_
#define RMAD_SYSTEM_HARDWARE_VERIFIER_CLIENT_H_

#include <string>
#include <vector>

namespace rmad {

class HardwareVerifierClient {
 public:
  HardwareVerifierClient() = default;
  virtual ~HardwareVerifierClient() = default;

  virtual bool GetHardwareVerificationResult(
      bool* is_compliant, std::vector<std::string>* error_strings) const = 0;
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_HARDWARE_VERIFIER_CLIENT_H_
