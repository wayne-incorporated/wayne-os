// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_manager.h"

#include <vector>

#include <gmock/gmock.h>

#include "shill/ethernet/mock_ethernet_provider.h"

using testing::_;
using testing::Invoke;
using testing::Return;

namespace shill {

MockManager::MockManager(ControlInterface* control_interface,
                         EventDispatcher* dispatcher,
                         Metrics* metrics)
    : Manager(control_interface, dispatcher, metrics, "", "", ""),
      mock_device_info_(nullptr),
      mock_ethernet_provider_(new MockEthernetProvider()) {
  const int64_t kSuspendDurationUsecs = 1000000;

  EXPECT_CALL(*this, ethernet_provider())
      .WillRepeatedly(Return(mock_ethernet_provider_.get()));
  EXPECT_CALL(*this, device_info())
      .WillRepeatedly(Invoke(this, &MockManager::mock_device_info));
  ON_CALL(*this, GetSuspendDurationUsecs())
      .WillByDefault(Return(kSuspendDurationUsecs));
}

MockManager::MockManager(ControlInterface* control_interface,
                         EventDispatcher* dispatcher,
                         Metrics* metrics,
                         const std::string& run_directory,
                         const std::string& storage_directory,
                         const std::string& user_storage_directory)
    : Manager(control_interface,
              dispatcher,
              metrics,
              run_directory,
              storage_directory,
              user_storage_directory) {}

MockManager::~MockManager() = default;

}  // namespace shill
