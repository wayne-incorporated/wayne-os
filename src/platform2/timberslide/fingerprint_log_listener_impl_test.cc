// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "timberslide/fingerprint_log_listener_impl.h"

using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;

namespace timberslide {
namespace {

class FingerprintLogListenerImplMock : public FingerprintLogListenerImpl {
 public:
  MOCK_METHOD(bool, IsRebootLine, (const std::string&));
  MOCK_METHOD(bool, SendFingerprintMCUReboot, ());
};

TEST(FingerprintLogListenerImplTest,
     IsRebootLine_FeedbackReportLog_ExpectMatch) {
  FingerprintLogListenerImpl listener;
  EXPECT_TRUE(
      listener.IsRebootLine("[Image: RW, dartmonkey_v2.0.1873-b99b1b10c "
                            "2019-07-30 07:45:24 <email: 2>]"));
}

TEST(FingerprintLogListenerImplTest,
     IsRebootLine_StandardCrosFpLog_ExpectMatch) {
  FingerprintLogListenerImpl listener;
  EXPECT_TRUE(
      listener.IsRebootLine("[Image: RW, nocturne_fp_v2.2.110-b936c0a3c "
                            "2018-11-02 14:16:46 @swarm-cros-461"));
}

TEST(FingerprintLogListenerImplTest,
     IsRebootLine_StandardCrosFpLog_ExpectNoMatch) {
  FingerprintLogListenerImpl listener;
  EXPECT_FALSE(listener.IsRebootLine(
      "[Image: RO, hatch_fp_v2.0.2149-631b4461d private:v0.0.92-9afd891 "
      "2019-09-09 20:50:32 tomhughes@tomhughes-desktop.mtv.corp.google.com]"));
  EXPECT_FALSE(listener.IsRebootLine("[0.103361 RW verify OK]"));
}

TEST(FingerprintLogListenerImplTest, NewLogLine_FirstBoot) {
  NiceMock<FingerprintLogListenerImplMock> mock;
  EXPECT_CALL(mock, IsRebootLine).WillOnce(Return(true));
  EXPECT_CALL(mock, SendFingerprintMCUReboot).Times(0);
  mock.OnLogLine("foo");
}

TEST(FingerprintLogListenerImplTest, NewLogLine_ExpectReboot) {
  NiceMock<FingerprintLogListenerImplMock> mock;
  EXPECT_CALL(mock, IsRebootLine).WillRepeatedly(Return(true));
  EXPECT_CALL(mock, SendFingerprintMCUReboot).Times(1);
  mock.OnLogLine("foo1");
  mock.OnLogLine("foo2");
}

}  // namespace
}  // namespace timberslide
