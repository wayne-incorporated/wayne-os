// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_MOCK_SHILL_CLIENT_H_
#define RMAD_SYSTEM_MOCK_SHILL_CLIENT_H_

#include "rmad/system/shill_client.h"

#include <gmock/gmock.h>

namespace rmad {

class MockShillClient : public ShillClient {
 public:
  MockShillClient() = default;
  MockShillClient(const MockShillClient&) = delete;
  MockShillClient& operator=(const MockShillClient&) = delete;
  ~MockShillClient() override = default;

  MOCK_METHOD(bool, DisableCellular, (), (const, override));
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_MOCK_SHILL_CLIENT_H_
