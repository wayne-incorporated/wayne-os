// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_INIT_DAEMON_CONTROLLER_H_
#define LOGIN_MANAGER_MOCK_INIT_DAEMON_CONTROLLER_H_

#include <memory>
#include <string>
#include <vector>

#include <dbus/message.h>
#include <gmock/gmock.h>

#include "login_manager/init_daemon_controller.h"

namespace login_manager {

class MockInitDaemonController : public InitDaemonController {
 public:
  MockInitDaemonController();
  ~MockInitDaemonController() override;

  MOCK_METHOD(std::unique_ptr<dbus::Response>,
              TriggerImpulse,
              (const std::string&,
               const std::vector<std::string>&,
               TriggerMode),
              (override));
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_INIT_DAEMON_CONTROLLER_H_
