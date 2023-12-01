// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_MOCK_HARDWARE_VERIFIER_CLIENT_H_
#define RMAD_SYSTEM_MOCK_HARDWARE_VERIFIER_CLIENT_H_

#include "rmad/system/hardware_verifier_client.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>

namespace rmad {

class MockHardwareVerifierClient : public HardwareVerifierClient {
 public:
  MockHardwareVerifierClient() = default;
  ~MockHardwareVerifierClient() override = default;

  MOCK_METHOD(bool,
              GetHardwareVerificationResult,
              (bool*, std::vector<std::string>*),
              (const, override));
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_MOCK_HARDWARE_VERIFIER_CLIENT_H_
