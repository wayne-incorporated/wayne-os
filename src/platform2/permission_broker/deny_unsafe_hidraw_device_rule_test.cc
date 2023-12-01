// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_unsafe_hidraw_device_rule.h"

#include <vector>

#include <gtest/gtest.h>

#include "base/logging.h"

#define MAKE_DESCRIPTOR(array) GenerateReportDescriptor(array, sizeof(array))

namespace permission_broker {

namespace {

// Some invalid descriptors.
const uint8_t kInvalidDescriptor0[] = {0x1};
const uint8_t kInvalidDescriptor1[] = {0x6};
const uint8_t kInvalidDescriptor2[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// Interface descriptor contents from a LUFA TinyHID firmware.
const uint8_t kLUFATestFirmwareDescriptor[] = {
    0x6,  0x0,  0xff, 0x9,  0x1,  0xa1, 0x1,  0x9,  0x2, 0x15, 0x0,
    0x25, 0xff, 0x75, 0x8,  0x95, 0x8,  0x81, 0x2,  0x9, 0x3,  0x15,
    0x0,  0x25, 0xff, 0x75, 0x8,  0x95, 0x8,  0x91, 0x2, 0xc0};

// Interface descriptor contents from a Logitech G13 controller.
const uint8_t kLogitechG13Descriptor[] = {
    0x6,  0x0,  0xff, 0x9,  0x0,  0xa1, 0x1,  0x15, 0x0, 0x26, 0xff, 0x0,  0x9,
    0x1,  0x85, 0x1,  0x95, 0x7,  0x75, 0x8,  0x81, 0x2, 0x85, 0x3,  0x9,  0x2,
    0x96, 0xdf, 0x3,  0x91, 0x2,  0x85, 0x7,  0x9,  0x3, 0x95, 0x4,  0xb1, 0x2,
    0x85, 0x4,  0x9,  0x4,  0xb1, 0x2,  0x85, 0x5,  0x9, 0x5,  0xb1, 0x2,  0x85,
    0x6,  0x9,  0x6,  0x96, 0x1,  0x1,  0xb1, 0x2,  0xc0};

// Interface descriptor contents from the keyboard interface of GCS1784
// KVM Switch.
const uint8_t kSampleKeyboardDescriptor[] = {
    0x5,  0x1,  0x9,  0x6,  0xa1, 0x1,  0x5,  0x7,  0x19, 0xe0, 0x29,
    0xe7, 0x15, 0x0,  0x25, 0x1,  0x75, 0x1,  0x95, 0x8,  0x81, 0x2,
    0x95, 0x1,  0x75, 0x8,  0x81, 0x1,  0x95, 0x5,  0x75, 0x1,  0x5,
    0x8,  0x19, 0x1,  0x29, 0x5,  0x91, 0x2,  0x95, 0x1,  0x75, 0x3,
    0x91, 0x1,  0x5,  0x7,  0x95, 0x6,  0x75, 0x8,  0x15, 0x0,  0x26,
    0xff, 0x0,  0x19, 0x0,  0x2a, 0xff, 0x0,  0x81, 0x0,  0xc0};

// Interface descriptor contents from the mouse interface of an GCS1784
// KVM Switch.
const uint8_t kSampleMouseDescriptor[] = {
    0x5,  0x1,  0x9,  0x2,  0xa1, 0x1,  0x9, 0x1,  0xa1, 0x0,  0x5, 0x9,  0x19,
    0x1,  0x29, 0x5,  0x15, 0x0,  0x25, 0x1, 0x95, 0x5,  0x75, 0x1, 0x81, 0x2,
    0x95, 0x1,  0x75, 0x3,  0x81, 0x1,  0x5, 0x1,  0x9,  0x30, 0x9, 0x31, 0x9,
    0x38, 0x15, 0x81, 0x25, 0x7f, 0x75, 0x8, 0x95, 0x3,  0x81, 0x6, 0xc0, 0xc0};

HidReportDescriptor GenerateReportDescriptor(const uint8_t raw_data[],
                                             size_t size) {
  HidReportDescriptor descriptor;
  descriptor.size = size;
  memcpy(&descriptor.data[0], &raw_data[0], size);
  return descriptor;
}

bool IsDeviceSafe(const std::vector<HidUsage>& usages) {
  for (std::vector<HidUsage>::const_iterator iter = usages.begin();
       iter != usages.end(); ++iter) {
    if (DenyUnsafeHidrawDeviceRule::IsUnsafeUsage(*iter))
      return false;
  }
  return true;
}

}  // namespace

class DenyUnsafeHidrawDeviceRuleTest : public testing::Test {
 public:
  DenyUnsafeHidrawDeviceRuleTest() = default;
  DenyUnsafeHidrawDeviceRuleTest(const DenyUnsafeHidrawDeviceRuleTest&) =
      delete;
  DenyUnsafeHidrawDeviceRuleTest& operator=(
      const DenyUnsafeHidrawDeviceRuleTest&) = delete;

  ~DenyUnsafeHidrawDeviceRuleTest() override = default;
};

TEST_F(DenyUnsafeHidrawDeviceRuleTest, IgnoreInvalidDescriptors) {
  std::vector<HidUsage> usages;
  ASSERT_FALSE(HidrawSubsystemUdevRule::ParseToplevelCollectionUsages(
      MAKE_DESCRIPTOR(kInvalidDescriptor0), &usages));
  ASSERT_FALSE(HidrawSubsystemUdevRule::ParseToplevelCollectionUsages(
      MAKE_DESCRIPTOR(kInvalidDescriptor1), &usages));
  ASSERT_FALSE(HidrawSubsystemUdevRule::ParseToplevelCollectionUsages(
      MAKE_DESCRIPTOR(kInvalidDescriptor2), &usages));
}

TEST_F(DenyUnsafeHidrawDeviceRuleTest, IgnoreSafeDevices) {
  std::vector<HidUsage> usages;
  ASSERT_TRUE(HidrawSubsystemUdevRule::ParseToplevelCollectionUsages(
      MAKE_DESCRIPTOR(kLUFATestFirmwareDescriptor), &usages));
  ASSERT_EQ(1u, usages.size());
  ASSERT_TRUE(IsDeviceSafe(usages));

  usages.clear();
  ASSERT_TRUE(HidrawSubsystemUdevRule::ParseToplevelCollectionUsages(
      MAKE_DESCRIPTOR(kLogitechG13Descriptor), &usages));
  ASSERT_EQ(1u, usages.size());
  ASSERT_TRUE(IsDeviceSafe(usages));
}

TEST_F(DenyUnsafeHidrawDeviceRuleTest, DenyKeyboardAccess) {
  std::vector<HidUsage> usages;
  ASSERT_TRUE(HidrawSubsystemUdevRule::ParseToplevelCollectionUsages(
      MAKE_DESCRIPTOR(kSampleKeyboardDescriptor), &usages));
  ASSERT_EQ(1u, usages.size());
  ASSERT_FALSE(IsDeviceSafe(usages));
}

TEST_F(DenyUnsafeHidrawDeviceRuleTest, DenyMouseAccess) {
  std::vector<HidUsage> usages;
  ASSERT_TRUE(HidrawSubsystemUdevRule::ParseToplevelCollectionUsages(
      MAKE_DESCRIPTOR(kSampleMouseDescriptor), &usages));
  ASSERT_EQ(1u, usages.size());
  ASSERT_FALSE(IsDeviceSafe(usages));
}

}  // namespace permission_broker
