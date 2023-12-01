// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "midis/device_tracker.h"

#include <memory>
#include <utility>

#include <base/functional/bind.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <brillo/test_helpers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "midis/tests/test_helper.h"

namespace midis {

namespace {

const char kFakeName1[] = "Sample MIDI Device - 1";
const char kFakeManufacturer1[] = "Foo";
const uint32_t kFakeSysNum1 = 2;
const uint32_t kFakeDevNum1 = 0;
const uint32_t kFakeSubdevs1 = 1;
const uint32_t kFakeFlags1 = 7;

const char kFakeName2[] = "Sample MIDI Device - 2";
const char kFakeManufacturer2[] = "Bar";
const uint32_t kFakeSysNum2 = 3;
const uint32_t kFakeDevNum2 = 1;
const uint32_t kFakeSubdevs2 = 2;
const uint32_t kFakeFlags2 = 6;

bool FakeInPortSubscribeCallback(uint32_t device_id, uint32_t port_id) {
  NOTIMPLEMENTED();
  return true;
}

int FakeOutPortSubscribeCallback(uint32_t device_id, uint32_t port_id) {
  NOTIMPLEMENTED();
  return 0;
}

void FakeInPortDeleteCallback(uint32_t device_id, uint32_t port_id) {
  NOTIMPLEMENTED();
}

void FakeOutPortDeleteCallback(int alsa_out_port_id) {
  NOTIMPLEMENTED();
}

void FakeSendMidiDataCallback(int alsa_out_port_id,
                              const uint8_t* buf,
                              size_t buf_len) {
  NOTIMPLEMENTED();
}

}  // namespace

class DeviceTrackerTest : public ::testing::Test {
 protected:
  DeviceTracker tracker_;
};

// Check whether a 2 devices get successfully added to the devices map.
TEST_F(DeviceTrackerTest, Add2DevicesPositive) {
  // Since this test isn't testing the Device class functionality, it's OK
  // to set the callbacks to be no-ops.
  auto dev = std::make_unique<Device>(
      kFakeName1, kFakeManufacturer1, kFakeSysNum1, kFakeDevNum1, kFakeSubdevs1,
      kFakeFlags1, base::BindRepeating(&FakeInPortSubscribeCallback),
      base::BindRepeating(&FakeOutPortSubscribeCallback),
      base::BindRepeating(&FakeInPortDeleteCallback),
      base::BindRepeating(&FakeOutPortDeleteCallback),
      base::BindRepeating(&FakeSendMidiDataCallback),
      std::map<uint32_t, unsigned int>());
  tracker_.AddDevice(std::move(dev));

  auto dev2 = std::make_unique<Device>(
      kFakeName2, kFakeManufacturer2, kFakeSysNum2, kFakeDevNum2, kFakeSubdevs2,
      kFakeFlags2, base::BindRepeating(&FakeInPortSubscribeCallback),
      base::BindRepeating(&FakeOutPortSubscribeCallback),
      base::BindRepeating(&FakeInPortDeleteCallback),
      base::BindRepeating(&FakeOutPortDeleteCallback),
      base::BindRepeating(&FakeSendMidiDataCallback),
      std::map<uint32_t, unsigned int>());
  tracker_.AddDevice(std::move(dev2));

  EXPECT_EQ(2, tracker_.devices_.size());

  auto it = tracker_.devices_.begin();
  uint32_t device_id = it->first;
  Device const* device = it->second.get();
  EXPECT_THAT(device, DeviceMatcher(device_id, kFakeName1, kFakeManufacturer1));

  it++;
  device_id = it->first;
  device = it->second.get();
  EXPECT_THAT(device, DeviceMatcher(device_id, kFakeName2, kFakeManufacturer2));
}

// Check whether a device gets successfully added, then removed from the devices
// map.
TEST_F(DeviceTrackerTest, AddRemoveDevicePositive) {
  auto dev = std::make_unique<Device>(
      kFakeName1, kFakeManufacturer1, kFakeSysNum1, kFakeDevNum1, kFakeSubdevs1,
      kFakeFlags1, base::BindRepeating(&FakeInPortSubscribeCallback),
      base::BindRepeating(&FakeOutPortSubscribeCallback),
      base::BindRepeating(&FakeInPortDeleteCallback),
      base::BindRepeating(&FakeOutPortDeleteCallback),
      base::BindRepeating(&FakeSendMidiDataCallback),
      std::map<uint32_t, unsigned int>());
  tracker_.AddDevice(std::move(dev));
  EXPECT_EQ(1, tracker_.devices_.size());

  tracker_.RemoveDevice(kFakeSysNum1, kFakeDevNum1);
  EXPECT_EQ(0, tracker_.devices_.size());
}

// Check whether a device gets successfully added, but not removed.
TEST_F(DeviceTrackerTest, AddDeviceRemoveNegative) {
  auto dev = std::make_unique<Device>(
      kFakeName1, kFakeManufacturer1, kFakeSysNum1, kFakeDevNum1, kFakeSubdevs1,
      kFakeFlags1, base::BindRepeating(&FakeInPortSubscribeCallback),
      base::BindRepeating(&FakeOutPortSubscribeCallback),
      base::BindRepeating(&FakeInPortDeleteCallback),
      base::BindRepeating(&FakeOutPortDeleteCallback),
      base::BindRepeating(&FakeSendMidiDataCallback),
      std::map<uint32_t, unsigned int>());
  tracker_.AddDevice(std::move(dev));
  EXPECT_EQ(1, tracker_.devices_.size());

  tracker_.RemoveDevice(kFakeSysNum2, kFakeDevNum1);
  EXPECT_EQ(1, tracker_.devices_.size());
}

}  // namespace midis
