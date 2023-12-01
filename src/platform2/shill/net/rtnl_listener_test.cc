// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/rtnl_listener.h"

#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/net/rtnl_handler.h"
#include "shill/net/rtnl_message.h"

namespace shill {

namespace {

class RtnlWatcher {
 public:
  MOCK_METHOD(void, ListenerCallback, (const RTNLMessage&));
};

}  // namespace

class RTNLListenerTest : public testing::Test {
 public:
  void SetUp() override {
    // RTNLHandler is a singleton, there's no guarentee that it is not
    // setup/used by other unittests. Clear "listeners_" field before we run
    // tests.
    RTNLHandler::GetInstance()->listeners_.Clear();
  }

  void TearDown() override {
    ASSERT_TRUE(RTNLHandler::GetInstance()->listeners_.empty());
  }
};

TEST_F(RTNLListenerTest, NoRun) {
  testing::StrictMock<RtnlWatcher> mock_listener;
  RTNLListener listener(RTNLHandler::kRequestAddr,
                        base::BindRepeating(&RtnlWatcher::ListenerCallback,
                                            base::Unretained(&mock_listener)));
  RTNLMessage message;
  listener.NotifyEvent(RTNLHandler::kRequestLink, message);
}

TEST_F(RTNLListenerTest, Run) {
  testing::StrictMock<RtnlWatcher> mock_listener;
  RTNLListener listener(RTNLHandler::kRequestLink | RTNLHandler::kRequestAddr,
                        base::BindRepeating(&RtnlWatcher::ListenerCallback,
                                            base::Unretained(&mock_listener)));
  RTNLMessage message;
  EXPECT_CALL(mock_listener,
              ListenerCallback(testing::A<const RTNLMessage&>()));
  listener.NotifyEvent(RTNLHandler::kRequestLink, message);
}

}  // namespace shill
