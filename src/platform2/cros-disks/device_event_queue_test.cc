// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/device_event_queue.h"

#include <algorithm>

#include <gtest/gtest.h>

#include "cros-disks/device_event.h"

namespace cros_disks {

class DeviceEventQueueTest : public ::testing::Test {
 protected:
  // Returns true if two device event objects have the same event type
  // and device path.
  static bool CompareDeviceEvent(const DeviceEvent& event1,
                                 const DeviceEvent& event2) {
    return (event1.event_type == event2.event_type) &&
           (event1.device_path == event2.device_path);
  }

  // Returns true if the device event queue under test has the expected
  // events.
  bool VerifyDeviceEventQueue() {
    return std::equal(expected_events_.begin(), expected_events_.end(),
                      queue_.events().begin(), CompareDeviceEvent);
  }

  DeviceEventQueue queue_;
  DeviceEventList expected_events_;
};

TEST_F(DeviceEventQueueTest, Constructor) {
  EXPECT_TRUE(queue_.events().empty());
}

TEST_F(DeviceEventQueueTest, Remove) {
  queue_.Remove();
  EXPECT_TRUE(queue_.events().empty());

  DeviceEvent event1(DeviceEvent::kDiskAdded, "d1");
  DeviceEvent event2(DeviceEvent::kDiskAdded, "d2");
  DeviceEvent event3(DeviceEvent::kDiskAdded, "d3");

  queue_.Add(event1);
  queue_.Add(event2);
  expected_events_.push_front(event1);
  expected_events_.push_front(event2);

  queue_.Remove();
  expected_events_.pop_back();
  EXPECT_TRUE(VerifyDeviceEventQueue());

  queue_.Add(event3);
  expected_events_.push_front(event3);

  queue_.Remove();
  expected_events_.pop_back();
  EXPECT_TRUE(VerifyDeviceEventQueue());

  queue_.Remove();
  expected_events_.pop_back();
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddIgored) {
  // An Ignored event is discarded
  queue_.Add(DeviceEvent(DeviceEvent::kIgnored, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDeviceAdded) {
  // A DeviceAdded event is added
  queue_.Add(DeviceEvent(DeviceEvent::kDeviceAdded, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDeviceAdded, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDeviceScanned) {
  // A DeviceScanned event is discarded
  queue_.Add(DeviceEvent(DeviceEvent::kDeviceScanned, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDeviceRemoved) {
  // A DeviceRemoved event is added
  queue_.Add(DeviceEvent(DeviceEvent::kDeviceRemoved, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDeviceRemoved, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDeviceAddedAndDeviceRemoved) {
  // A DeviceAdded event followed by a DeviceRemoved event of the same
  // device path are both discarded
  queue_.Add(DeviceEvent(DeviceEvent::kDeviceAdded, "d1"));
  queue_.Add(DeviceEvent(DeviceEvent::kDeviceRemoved, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());

  queue_.Add(DeviceEvent(DeviceEvent::kDeviceAdded, "d1"));
  queue_.Add(DeviceEvent(DeviceEvent::kDeviceRemoved, "d2"));
  queue_.Add(DeviceEvent(DeviceEvent::kDeviceRemoved, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDeviceRemoved, "d2"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDeviceRemovedAndDeviceAdded) {
  queue_.Add(DeviceEvent(DeviceEvent::kDeviceRemoved, "d1"));
  queue_.Add(DeviceEvent(DeviceEvent::kDeviceAdded, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDeviceRemoved, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDeviceAdded, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDiskAdded) {
  // A DiskAdded event is added
  queue_.Add(DeviceEvent(DeviceEvent::kDiskAdded, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDiskAdded, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDiskChanged) {
  // A DiskChanged event is added if no DiskAdded event has been added
  queue_.Add(DeviceEvent(DeviceEvent::kDiskChanged, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDiskChanged, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());

  // Further DiskChanged events are combined and the latest one is kept
  queue_.Add(DeviceEvent(DeviceEvent::kDiskChanged, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());

  queue_.Add(DeviceEvent(DeviceEvent::kDiskChanged, "d2"));
  queue_.Add(DeviceEvent(DeviceEvent::kDiskChanged, "d1"));
  expected_events_.clear();
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDiskChanged, "d2"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDiskChanged, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDiskRemoved) {
  // A DiskRemoved event is added
  queue_.Add(DeviceEvent(DeviceEvent::kDiskRemoved, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDiskRemoved, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDiskAddedAndDiskRemoved) {
  // A DiskAdded event followed by a DiskRemoved event
  // of the same device path are both discarded
  queue_.Add(DeviceEvent(DeviceEvent::kDiskAdded, "d1"));
  queue_.Add(DeviceEvent(DeviceEvent::kDiskRemoved, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());

  queue_.Add(DeviceEvent(DeviceEvent::kDiskAdded, "d1"));
  queue_.Add(DeviceEvent(DeviceEvent::kDiskRemoved, "d2"));
  queue_.Add(DeviceEvent(DeviceEvent::kDiskRemoved, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDiskRemoved, "d2"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDiskAddedAndDiskChanged) {
  // A DiskChanged event is discarded if a DiskAdded event of the same
  // same device path is in the queue
  queue_.Add(DeviceEvent(DeviceEvent::kDiskAdded, "d1"));
  queue_.Add(DeviceEvent(DeviceEvent::kDiskChanged, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDiskAdded, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());

  queue_.Add(DeviceEvent(DeviceEvent::kDiskAdded, "d2"));
  queue_.Add(DeviceEvent(DeviceEvent::kDiskChanged, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDiskAdded, "d2"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDiskChangedAndDiskRemoved) {
  // A DiskChanged event followed by a DiskRemoved event
  // of the same device path are both discarded
  queue_.Add(DeviceEvent(DeviceEvent::kDiskChanged, "d1"));
  queue_.Add(DeviceEvent(DeviceEvent::kDiskRemoved, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());

  queue_.Add(DeviceEvent(DeviceEvent::kDiskChanged, "d1"));
  queue_.Add(DeviceEvent(DeviceEvent::kDiskRemoved, "d2"));
  queue_.Add(DeviceEvent(DeviceEvent::kDiskRemoved, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDiskRemoved, "d2"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, AddDiskRemovedAndDiskAdded) {
  // A DiskRemoved event followed by a DiskAdded event of the same
  // device path are both added to the queue
  queue_.Add(DeviceEvent(DeviceEvent::kDiskRemoved, "d1"));
  queue_.Add(DeviceEvent(DeviceEvent::kDiskAdded, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDiskRemoved, "d1"));
  expected_events_.push_front(DeviceEvent(DeviceEvent::kDiskAdded, "d1"));
  EXPECT_TRUE(VerifyDeviceEventQueue());
}

TEST_F(DeviceEventQueueTest, Head) {
  EXPECT_EQ(nullptr, queue_.Head());

  DeviceEvent event1(DeviceEvent::kDiskAdded, "d1");
  DeviceEvent event2(DeviceEvent::kDiskAdded, "d2");
  DeviceEvent event3(DeviceEvent::kDiskAdded, "d3");

  queue_.Add(event1);
  EXPECT_NE(nullptr, queue_.Head());
  EXPECT_TRUE(CompareDeviceEvent(event1, *queue_.Head()));

  queue_.Add(event2);
  EXPECT_NE(nullptr, queue_.Head());
  EXPECT_TRUE(CompareDeviceEvent(event1, *queue_.Head()));

  queue_.Remove();
  EXPECT_NE(nullptr, queue_.Head());
  EXPECT_TRUE(CompareDeviceEvent(event2, *queue_.Head()));

  queue_.Add(event3);
  EXPECT_NE(nullptr, queue_.Head());
  EXPECT_TRUE(CompareDeviceEvent(event2, *queue_.Head()));

  queue_.Remove();
  EXPECT_NE(nullptr, queue_.Head());
  EXPECT_TRUE(CompareDeviceEvent(event3, *queue_.Head()));

  queue_.Remove();
  EXPECT_EQ(nullptr, queue_.Head());
}

}  // namespace cros_disks
