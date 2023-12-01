// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/supplicant/supplicant_manager.h"

#include <memory>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/supplicant/mock_supplicant_process_proxy.h"
#include "shill/test_event_dispatcher.h"

using testing::_;
using testing::InSequence;
using testing::NiceMock;
using testing::Test;

namespace shill {

class SupplicantManagerTest : public Test {
 public:
  SupplicantManagerTest()
      : manager_(&control_interface_, &dispatcher_, &metrics_),
        supplicant_manager_(manager_.supplicant_manager()),
        callback_(
            base::BindRepeating(&SupplicantManagerTest::SupplicantPresence,
                                base::Unretained(this))) {
    supplicant_manager_->Start();
  }

 protected:
  MOCK_METHOD(void, SupplicantPresence, (bool));

  EventDispatcherForTest dispatcher_;
  MockControl control_interface_;
  NiceMock<MockMetrics> metrics_;
  MockManager manager_;
  SupplicantManager* supplicant_manager_;
  SupplicantManager::SupplicantListenerCallback callback_;
};

TEST_F(SupplicantManagerTest, Appear) {
  SupplicantManager::ScopedSupplicantListener listener(supplicant_manager_,
                                                       callback_);
  EXPECT_CALL(*this, SupplicantPresence(true)).Times(1);
  control_interface_.supplicant_appear().Run();
  dispatcher_.DispatchPendingEvents();
}

TEST_F(SupplicantManagerTest, Disappear) {
  SupplicantManager::ScopedSupplicantListener listener(supplicant_manager_,
                                                       callback_);
  {
    InSequence s;
    EXPECT_CALL(*this, SupplicantPresence(true)).Times(1);
    EXPECT_CALL(*this, SupplicantPresence(false)).Times(1);
  }
  control_interface_.supplicant_appear().Run();
  control_interface_.supplicant_vanish().Run();
  dispatcher_.DispatchPendingEvents();
}

TEST_F(SupplicantManagerTest, AlreadyPresent) {
  control_interface_.supplicant_appear().Run();
  SupplicantManager::ScopedSupplicantListener listener(supplicant_manager_,
                                                       callback_);
  EXPECT_CALL(*this, SupplicantPresence(true)).Times(1);
  dispatcher_.DispatchPendingEvents();
}

}  // namespace shill
