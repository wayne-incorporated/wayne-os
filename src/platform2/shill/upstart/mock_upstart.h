// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_UPSTART_MOCK_UPSTART_H_
#define SHILL_UPSTART_MOCK_UPSTART_H_

#include <gmock/gmock.h>

#include "shill/upstart/upstart.h"

namespace shill {

class MockUpstart : public Upstart {
 public:
  explicit MockUpstart(ControlInterface* control_interface);
  MockUpstart(const MockUpstart&) = delete;
  MockUpstart& operator=(const MockUpstart&) = delete;

  ~MockUpstart() override;

  MOCK_METHOD(void, NotifyDisconnected, (), (override));
  MOCK_METHOD(void, NotifyConnected, (), (override));
};

}  // namespace shill

#endif  // SHILL_UPSTART_MOCK_UPSTART_H_
