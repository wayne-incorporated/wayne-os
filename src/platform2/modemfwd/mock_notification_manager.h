// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_MOCK_NOTIFICATION_MANAGER_H_
#define MODEMFWD_MOCK_NOTIFICATION_MANAGER_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "modemfwd/notification_manager.h"

namespace modemfwd {

class MockNotificationManager : public NotificationManager {
 public:
  MockNotificationManager() {}
  ~MockNotificationManager() override = default;

  MOCK_METHOD(void,
              NotifyUpdateFirmwareCompletedSuccess,
              (bool, uint32_t),
              (override));
  MOCK_METHOD(void,
              NotifyUpdateFirmwareCompletedFailure,
              (const brillo::Error*),
              (override));
  MOCK_METHOD(void,
              NotifyUpdateFirmwareCompletedFlashFailure,
              (const brillo::Error*, uint32_t),
              (override));
};

}  // namespace modemfwd

#endif  // MODEMFWD_MOCK_NOTIFICATION_MANAGER_H_
