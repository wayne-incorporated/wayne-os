// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/device_event_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(DeviceEventCommand, DeviceEventCommandGet) {
  // Constructor for getting device event mask.
  DeviceEventCommand cmd(false);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_DEVICE_EVENT);
  EXPECT_EQ(cmd.Req()->param, EC_DEVICE_EVENT_PARAM_GET_ENABLED_EVENTS);
  EXPECT_EQ(cmd.Req()->event_mask, 0);
}

TEST(DeviceEventCommand, DeviceEventCommandGetAndClear) {
  // Constructor for getting (and clearing) pending device events.
  DeviceEventCommand cmd(true);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_DEVICE_EVENT);
  EXPECT_EQ(cmd.Req()->param, EC_DEVICE_EVENT_PARAM_GET_CURRENT_EVENTS);
  EXPECT_EQ(cmd.Req()->event_mask, 0);
}

TEST(DeviceEventCommand, DeviceEventCommandEnableTrackpad) {
  // Constructor for setting device event mask.
  DeviceEventCommand cmd(EC_DEVICE_EVENT_TRACKPAD, true,
                         EC_DEVICE_EVENT_MASK(EC_DEVICE_EVENT_DSP));
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_DEVICE_EVENT);
  EXPECT_EQ(cmd.Req()->param, EC_DEVICE_EVENT_PARAM_SET_ENABLED_EVENTS);
  EXPECT_EQ(cmd.Req()->event_mask, 3);
}

TEST(DeviceEventCommand, DeviceEventCommandDisableTrackpad) {
  // Constructor for clearing device event mask.
  DeviceEventCommand cmd(EC_DEVICE_EVENT_TRACKPAD, false,
                         EC_DEVICE_EVENT_MASK(EC_DEVICE_EVENT_TRACKPAD));
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_DEVICE_EVENT);
  EXPECT_EQ(cmd.Req()->param, EC_DEVICE_EVENT_PARAM_SET_ENABLED_EVENTS);
  EXPECT_EQ(cmd.Req()->event_mask, 0);
}

// Mock the underlying EcCommand to test.
class DeviceEventCommandTest : public testing::Test {
 public:
  class MockDeviceEventCommand : public DeviceEventCommand {
   public:
    using DeviceEventCommand::DeviceEventCommand;
    MOCK_METHOD(const struct ec_response_device_event*,
                Resp,
                (),
                (const, override));
  };
};

TEST_F(DeviceEventCommandTest, Success) {
  MockDeviceEventCommand mock_command(false);
  struct ec_response_device_event response = {
      .event_mask = EC_DEVICE_EVENT_MASK(EC_DEVICE_EVENT_WLC)};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_TRUE(mock_command.IsEnabled(EC_DEVICE_EVENT_WLC));
  EXPECT_FALSE(mock_command.IsEnabled(EC_DEVICE_EVENT_TRACKPAD));
  EXPECT_FALSE(mock_command.IsEnabled(EC_DEVICE_EVENT_DSP));
  EXPECT_FALSE(mock_command.IsEnabled(EC_DEVICE_EVENT_WIFI));

  EXPECT_EQ(mock_command.GetMask(), 8);
}

TEST_F(DeviceEventCommandTest, Set) {
  MockDeviceEventCommand mock_command(EC_DEVICE_EVENT_WLC, true, 0);
  struct ec_response_device_event response = {
      .event_mask = EC_DEVICE_EVENT_MASK(EC_DEVICE_EVENT_WLC)};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_TRUE(mock_command.IsEnabled(EC_DEVICE_EVENT_WLC));
  EXPECT_FALSE(mock_command.IsEnabled(EC_DEVICE_EVENT_TRACKPAD));
  EXPECT_FALSE(mock_command.IsEnabled(EC_DEVICE_EVENT_DSP));
  EXPECT_FALSE(mock_command.IsEnabled(EC_DEVICE_EVENT_WIFI));

  EXPECT_EQ(mock_command.GetMask(), 8);
}

}  // namespace
}  // namespace ec
