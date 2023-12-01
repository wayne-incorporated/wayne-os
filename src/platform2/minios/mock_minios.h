// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_MINIOS_H_
#define MINIOS_MOCK_MINIOS_H_

#include <string>

#include <gmock/gmock.h>

#include "minios/minios_interface.h"

namespace minios {

class MockMiniOs : public MiniOsInterface {
 public:
  MockMiniOs() = default;

  MOCK_METHOD(bool,
              GetState,
              (State * state_out, brillo::ErrorPtr* err),
              (override));

  MOCK_METHOD(bool, NextScreen, (brillo::ErrorPtr * err), (override));

  MOCK_METHOD(bool, PrevScreen, (brillo::ErrorPtr * err), (override));

  MOCK_METHOD(bool, Reset, (brillo::ErrorPtr * err), (override));

  MOCK_METHOD(void,
              SetNetworkCredentials,
              (const std::string& in_ssid, const std::string& in_passphrase),
              (override));

  MOCK_METHOD(void, PressKey, (uint32_t in_keycode), (override));

  MOCK_METHOD(void,
              StartRecovery,
              (const std::string& in_ssid, const std::string& in_passphrase),
              (override));

 private:
  MockMiniOs(const MockMiniOs&) = delete;
  MockMiniOs& operator=(const MockMiniOs&) = delete;
};

}  // namespace minios

#endif  // MINIOS_MOCK_MINIOS_H_
