// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_MOCK_SUPPLICANT_EAP_STATE_HANDLER_H_
#define SHILL_SUPPLICANT_MOCK_SUPPLICANT_EAP_STATE_HANDLER_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/supplicant/supplicant_eap_state_handler.h"

namespace shill {

class MockSupplicantEAPStateHandler : public SupplicantEAPStateHandler {
 public:
  MockSupplicantEAPStateHandler();
  MockSupplicantEAPStateHandler(const MockSupplicantEAPStateHandler&) = delete;
  MockSupplicantEAPStateHandler& operator=(
      const MockSupplicantEAPStateHandler&) = delete;

  ~MockSupplicantEAPStateHandler() override;

  MOCK_METHOD(bool,
              ParseStatus,
              (const std::string&,
               const std::string&,
               Service::ConnectFailure*),
              (override));
  MOCK_METHOD(void, Reset, (), (override));
  MOCK_METHOD(bool, is_eap_in_progress, (), (const, override));
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_MOCK_SUPPLICANT_EAP_STATE_HANDLER_H_
