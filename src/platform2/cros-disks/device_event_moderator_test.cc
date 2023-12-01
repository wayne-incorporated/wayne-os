// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/device_event_moderator.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/device_event.h"
#include "cros-disks/device_event_dispatcher_interface.h"
#include "cros-disks/device_event_source_interface.h"

using testing::_;
using testing::DoAll;
using testing::InSequence;
using testing::Return;
using testing::SetArgPointee;

namespace cros_disks {

class MockDeviceEventDispatcher : public DeviceEventDispatcherInterface {
 public:
  MOCK_METHOD(void, DispatchDeviceEvent, (const DeviceEvent&), (override));
};

class MockDeviceEventSource : public DeviceEventSourceInterface {
 public:
  MOCK_METHOD(bool, GetDeviceEvents, (DeviceEventList*), (override));
};

class DeviceEventModeratorTest : public ::testing::Test {
 public:
  DeviceEventModeratorTest()
      : moderator_(
            new DeviceEventModerator(&event_dispatcher_, &event_source_, true)),
        event1_(DeviceEvent::kDeviceAdded, "1"),
        event2_(DeviceEvent::kDeviceAdded, "2"),
        event_list1_({event1_}),
        event_list2_({event2_}),
        event_list3_({event1_, event2_}) {}

 protected:
  void RecreateDeviceEventModerator(bool dispatch_initially) {
    moderator_.reset(new DeviceEventModerator(
        &event_dispatcher_, &event_source_, dispatch_initially));
  }

  MockDeviceEventDispatcher event_dispatcher_;
  MockDeviceEventSource event_source_;
  std::unique_ptr<DeviceEventModerator> moderator_;
  DeviceEvent event1_, event2_;
  DeviceEventList event_list1_, event_list2_, event_list3_;
};

TEST_F(DeviceEventModeratorTest, DispatchQueuedDeviceEventsWithEmptyQueue) {
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(_)).Times(0);
  moderator_->DispatchQueuedDeviceEvents();
}

TEST_F(DeviceEventModeratorTest, EventsProcessedNoSessionManager) {
  RecreateDeviceEventModerator(/* dispatch_initially= */ false);
  EXPECT_FALSE(moderator_->is_event_queued());

  InSequence sequence;
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(DoAll(SetArgPointee<0>(event_list1_), Return(true)))
      .RetiresOnSaturation();
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event1_));
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(Return(false))
      .RetiresOnSaturation();
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(DoAll(SetArgPointee<0>(event_list2_), Return(true)))
      .RetiresOnSaturation();
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event2_));

  moderator_->OnScreenIsUnlocked();
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
}

TEST_F(DeviceEventModeratorTest, OnScreenIsLocked) {
  InSequence sequence;
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(DoAll(SetArgPointee<0>(event_list1_), Return(true)))
      .WillOnce(Return(false))
      .WillOnce(DoAll(SetArgPointee<0>(event_list2_), Return(true)));
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(_)).Times(0);

  moderator_->OnScreenIsLocked();
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
  EXPECT_TRUE(moderator_->is_event_queued());
}

TEST_F(DeviceEventModeratorTest, OnScreenIsLockedAndThenUnlocked) {
  InSequence sequence;
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(DoAll(SetArgPointee<0>(event_list1_), Return(true)))
      .WillOnce(Return(false))
      .WillOnce(DoAll(SetArgPointee<0>(event_list2_), Return(true)));
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event1_));
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event2_));

  moderator_->OnScreenIsLocked();
  EXPECT_TRUE(moderator_->is_event_queued());
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
  moderator_->OnScreenIsUnlocked();
  EXPECT_FALSE(moderator_->is_event_queued());
}

TEST_F(DeviceEventModeratorTest, OnScreenIsUnlocked) {
  InSequence sequence;
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(DoAll(SetArgPointee<0>(event_list1_), Return(true)))
      .RetiresOnSaturation();
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event1_));
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(Return(false))
      .RetiresOnSaturation();
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(DoAll(SetArgPointee<0>(event_list2_), Return(true)))
      .RetiresOnSaturation();
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event2_));

  moderator_->OnScreenIsUnlocked();
  EXPECT_FALSE(moderator_->is_event_queued());
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
}

TEST_F(DeviceEventModeratorTest, OnSessionStarted) {
  InSequence sequence;
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(DoAll(SetArgPointee<0>(event_list1_), Return(true)))
      .RetiresOnSaturation();
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event1_));
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(Return(false))
      .RetiresOnSaturation();
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(DoAll(SetArgPointee<0>(event_list2_), Return(true)))
      .RetiresOnSaturation();
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event2_));

  moderator_->OnSessionStarted();
  EXPECT_FALSE(moderator_->is_event_queued());
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
}

TEST_F(DeviceEventModeratorTest, OnSessionStopped) {
  InSequence sequence;
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(DoAll(SetArgPointee<0>(event_list1_), Return(true)))
      .WillOnce(Return(false))
      .WillOnce(DoAll(SetArgPointee<0>(event_list2_), Return(true)));
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(_)).Times(0);

  moderator_->OnSessionStopped();
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
  EXPECT_TRUE(moderator_->is_event_queued());
}

TEST_F(DeviceEventModeratorTest, OnSessionStoppedAndThenStarted) {
  InSequence sequence;
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(DoAll(SetArgPointee<0>(event_list1_), Return(true)))
      .WillOnce(Return(false))
      .WillOnce(DoAll(SetArgPointee<0>(event_list2_), Return(true)));
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event1_));
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event2_));

  moderator_->OnSessionStopped();
  EXPECT_TRUE(moderator_->is_event_queued());
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
  moderator_->ProcessDeviceEvents();
  moderator_->OnSessionStarted();
  EXPECT_FALSE(moderator_->is_event_queued());
}

TEST_F(DeviceEventModeratorTest, GetDeviceEventsReturningMultipleEvents) {
  InSequence sequence;
  EXPECT_CALL(event_source_, GetDeviceEvents(_))
      .WillOnce(DoAll(SetArgPointee<0>(event_list3_), Return(true)));
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event1_));
  EXPECT_CALL(event_dispatcher_, DispatchDeviceEvent(event2_));

  moderator_->OnSessionStarted();
  moderator_->ProcessDeviceEvents();
}

}  // namespace cros_disks
