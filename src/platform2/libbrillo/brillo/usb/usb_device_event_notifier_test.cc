// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_device_event_notifier.h"

#include <utility>

#include <brillo/udev/mock_udev.h>
#include <brillo/udev/mock_udev_device.h>
#include <brillo/udev/mock_udev_enumerate.h>
#include <brillo/udev/mock_udev_list_entry.h>
#include <brillo/udev/mock_udev_monitor.h>
#include <gtest/gtest.h>

#include "brillo/usb/mock_usb_device_event_observer.h"

using testing::_;
using testing::ByMove;
using testing::InSequence;
using testing::Return;
using testing::StrEq;

namespace brillo {

namespace {

const char kUdevActionAdd[] = "add";
const char kUdevActionChange[] = "change";
const char kUdevActionRemove[] = "remove";

const char kFakeUsbDevice1SysPath[] = "/sys/devices/fake/1";
const uint16_t kFakeUsbDevice1BusNumber = 1;
const char kFakeUsbDevice1BusNumberString[] = "1";
const uint16_t kFakeUsbDevice1DeviceAddress = 2;
const char kFakeUsbDevice1DeviceAddressString[] = "2";
const uint16_t kFakeUsbDevice1VendorId = 0x0123;
const char kFakeUsbDevice1VendorIdString[] = "0123";
const uint16_t kFakeUsbDevice1ProductId = 0x4567;
const char kFakeUsbDevice1ProductIdString[] = "4567";

const char kFakeUsbDevice2SysPath[] = "/sys/devices/fake/2";
const uint16_t kFakeUsbDevice2BusNumber = 3;
const char kFakeUsbDevice2BusNumberString[] = "3";
const uint16_t kFakeUsbDevice2DeviceAddress = 4;
const char kFakeUsbDevice2DeviceAddressString[] = "4";
const uint16_t kFakeUsbDevice2VendorId = 0x89ab;
const char kFakeUsbDevice2VendorIdString[] = "89ab";
const uint16_t kFakeUsbDevice2ProductId = 0xcdef;
const char kFakeUsbDevice2ProductIdString[] = "cdef";

}  // namespace

class UsbDeviceEventNotifierTest : public testing::Test {
 protected:
  UsbDeviceEventNotifierTest() : notifier_(&udev_) {}

  brillo::MockUdev udev_;
  MockUsbDeviceEventObserver observer_;
  UsbDeviceEventNotifier notifier_;
};

TEST(UsbDeviceEventNotifierStaticTest, ConvertNullToEmptyString) {
  EXPECT_EQ("", UsbDeviceEventNotifier::ConvertNullToEmptyString(nullptr));
  EXPECT_EQ("", UsbDeviceEventNotifier::ConvertNullToEmptyString(""));
  EXPECT_EQ("a", UsbDeviceEventNotifier::ConvertNullToEmptyString("a"));
  EXPECT_EQ("test string",
            UsbDeviceEventNotifier::ConvertNullToEmptyString("test string"));
}

TEST(UsbDeviceEventNotifierStaticTest, ConvertHexStringToUint16) {
  uint16_t value = 0x0000;

  EXPECT_FALSE(UsbDeviceEventNotifier::ConvertHexStringToUint16("", &value));
  EXPECT_FALSE(UsbDeviceEventNotifier::ConvertHexStringToUint16("0", &value));
  EXPECT_FALSE(UsbDeviceEventNotifier::ConvertHexStringToUint16("00", &value));
  EXPECT_FALSE(UsbDeviceEventNotifier::ConvertHexStringToUint16("000", &value));
  EXPECT_FALSE(
      UsbDeviceEventNotifier::ConvertHexStringToUint16("00000", &value));
  EXPECT_FALSE(
      UsbDeviceEventNotifier::ConvertHexStringToUint16("000z", &value));

  EXPECT_TRUE(UsbDeviceEventNotifier::ConvertHexStringToUint16("abcd", &value));
  EXPECT_EQ(0xabcd, value);

  EXPECT_TRUE(UsbDeviceEventNotifier::ConvertHexStringToUint16("0000", &value));
  EXPECT_EQ(0x0000, value);

  EXPECT_TRUE(UsbDeviceEventNotifier::ConvertHexStringToUint16("ffff", &value));
  EXPECT_EQ(0xffff, value);
}

TEST(UsbDeviceEventNotifierStaticTest, ConvertStringToUint8) {
  uint8_t value = 0;

  EXPECT_FALSE(UsbDeviceEventNotifier::ConvertStringToUint8("", &value));
  EXPECT_FALSE(UsbDeviceEventNotifier::ConvertStringToUint8("z", &value));
  EXPECT_FALSE(UsbDeviceEventNotifier::ConvertStringToUint8("-1", &value));
  EXPECT_FALSE(UsbDeviceEventNotifier::ConvertStringToUint8("256", &value));

  EXPECT_TRUE(UsbDeviceEventNotifier::ConvertStringToUint8("1", &value));
  EXPECT_EQ(1, value);

  EXPECT_TRUE(UsbDeviceEventNotifier::ConvertStringToUint8("0", &value));
  EXPECT_EQ(0, value);

  EXPECT_TRUE(UsbDeviceEventNotifier::ConvertStringToUint8("255", &value));
  EXPECT_EQ(255, value);
}

TEST(UsbDeviceEventNotifierStaticTest, GetDeviceAttributes) {
  uint8_t bus_number;
  uint8_t device_address;
  uint16_t vendor_id;
  uint16_t product_id;

  // Invalid bus number.
  brillo::MockUdevDevice device1;
  EXPECT_CALL(device1, GetSysAttributeValue(_)).WillOnce(Return(""));
  EXPECT_FALSE(UsbDeviceEventNotifier::GetDeviceAttributes(
      &device1, &bus_number, &device_address, &vendor_id, &product_id));

  // Invalid device address.
  brillo::MockUdevDevice device2;
  EXPECT_CALL(device2, GetSysAttributeValue(_))
      .WillOnce(Return(kFakeUsbDevice1BusNumberString))
      .WillOnce(Return(""));
  EXPECT_FALSE(UsbDeviceEventNotifier::GetDeviceAttributes(
      &device2, &bus_number, &device_address, &vendor_id, &product_id));

  // Invalid vendor ID.
  brillo::MockUdevDevice device3;
  EXPECT_CALL(device3, GetSysAttributeValue(_))
      .WillOnce(Return(kFakeUsbDevice1BusNumberString))
      .WillOnce(Return(kFakeUsbDevice1DeviceAddressString))
      .WillOnce(Return(""));
  EXPECT_FALSE(UsbDeviceEventNotifier::GetDeviceAttributes(
      &device3, &bus_number, &device_address, &vendor_id, &product_id));

  // Invalid product ID.
  brillo::MockUdevDevice device4;
  EXPECT_CALL(device4, GetSysAttributeValue(_))
      .WillOnce(Return(kFakeUsbDevice1BusNumberString))
      .WillOnce(Return(kFakeUsbDevice1DeviceAddressString))
      .WillOnce(Return(kFakeUsbDevice1VendorIdString))
      .WillOnce(Return(""));
  EXPECT_FALSE(UsbDeviceEventNotifier::GetDeviceAttributes(
      &device4, &bus_number, &device_address, &vendor_id, &product_id));

  // Valid bus number, device address, vendor ID, and product ID.
  brillo::MockUdevDevice device5;
  EXPECT_CALL(device5, GetSysAttributeValue(_))
      .WillOnce(Return(kFakeUsbDevice1BusNumberString))
      .WillOnce(Return(kFakeUsbDevice1DeviceAddressString))
      .WillOnce(Return(kFakeUsbDevice1VendorIdString))
      .WillOnce(Return(kFakeUsbDevice1ProductIdString));
  EXPECT_TRUE(UsbDeviceEventNotifier::GetDeviceAttributes(
      &device5, &bus_number, &device_address, &vendor_id, &product_id));
  EXPECT_EQ(kFakeUsbDevice1BusNumber, bus_number);
  EXPECT_EQ(kFakeUsbDevice1DeviceAddress, device_address);
  EXPECT_EQ(kFakeUsbDevice1VendorId, vendor_id);
  EXPECT_EQ(kFakeUsbDevice1ProductId, product_id);
}

TEST_F(UsbDeviceEventNotifierTest, OnUsbDeviceEvents) {
  auto device1 = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device1, GetSysPath()).WillOnce(Return(kFakeUsbDevice1SysPath));
  EXPECT_CALL(*device1, GetAction()).WillOnce(Return(kUdevActionAdd));

  auto device2 = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device2, GetSysPath()).WillOnce(Return(kFakeUsbDevice2SysPath));
  EXPECT_CALL(*device2, GetAction()).WillOnce(Return(kUdevActionAdd));
  EXPECT_CALL(*device2, GetSysAttributeValue(_))
      .WillOnce(Return(kFakeUsbDevice2BusNumberString))
      .WillOnce(Return(kFakeUsbDevice2DeviceAddressString))
      .WillOnce(Return(kFakeUsbDevice2VendorIdString))
      .WillOnce(Return(kFakeUsbDevice2ProductIdString));

  auto device3 = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device3, GetSysPath()).WillOnce(Return(kFakeUsbDevice1SysPath));
  EXPECT_CALL(*device3, GetAction()).WillOnce(Return(kUdevActionRemove));

  auto device4 = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device4, GetSysPath()).WillOnce(Return(kFakeUsbDevice2SysPath));
  EXPECT_CALL(*device4, GetAction()).WillOnce(Return(kUdevActionRemove));

  auto monitor = std::make_unique<brillo::MockUdevMonitor>();
  EXPECT_CALL(*monitor, ReceiveDevice())
      .WillOnce(Return(ByMove(std::move(device1))))
      .WillOnce(Return(ByMove(std::move(device2))))
      .WillOnce(Return(ByMove(std::move(device3))))
      .WillOnce(Return(ByMove(std::move(device4))));
  notifier_.udev_monitor_ = std::move(monitor);

  EXPECT_CALL(
      observer_,
      OnUsbDeviceAdded(kFakeUsbDevice2SysPath, kFakeUsbDevice2BusNumber,
                       kFakeUsbDevice2DeviceAddress, kFakeUsbDevice2VendorId,
                       kFakeUsbDevice2ProductId));
  EXPECT_CALL(observer_, OnUsbDeviceRemoved(kFakeUsbDevice1SysPath));

  notifier_.OnUdevMonitorFileDescriptorReadable();
  notifier_.AddObserver(&observer_);
  notifier_.OnUdevMonitorFileDescriptorReadable();
  notifier_.OnUdevMonitorFileDescriptorReadable();
  notifier_.RemoveObserver(&observer_);
  notifier_.OnUdevMonitorFileDescriptorReadable();
}

TEST_F(UsbDeviceEventNotifierTest, OnUsbDeviceEventNotAddOrRemove) {
  auto device = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device, GetSysPath()).WillOnce(Return(kFakeUsbDevice1SysPath));
  EXPECT_CALL(*device, GetAction()).WillOnce(Return(kUdevActionChange));

  auto monitor = std::make_unique<brillo::MockUdevMonitor>();
  EXPECT_CALL(*monitor, ReceiveDevice())
      .WillOnce(Return(ByMove(std::move(device))));
  notifier_.udev_monitor_ = std::move(monitor);

  EXPECT_CALL(observer_, OnUsbDeviceAdded(_, _, _, _, _)).Times(0);
  EXPECT_CALL(observer_, OnUsbDeviceRemoved(_)).Times(0);
  notifier_.AddObserver(&observer_);
  notifier_.OnUdevMonitorFileDescriptorReadable();
}

TEST_F(UsbDeviceEventNotifierTest, OnUsbDeviceEventWithInvalidBusNumber) {
  auto device = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device, GetSysPath()).WillOnce(Return(kFakeUsbDevice1SysPath));
  EXPECT_CALL(*device, GetAction()).WillOnce(Return(kUdevActionAdd));
  EXPECT_CALL(*device, GetSysAttributeValue(_)).WillOnce(Return(""));

  auto monitor = std::make_unique<brillo::MockUdevMonitor>();
  EXPECT_CALL(*monitor, ReceiveDevice())
      .WillOnce(Return(ByMove(std::move(device))));
  notifier_.udev_monitor_ = std::move(monitor);

  EXPECT_CALL(observer_, OnUsbDeviceAdded(_, _, _, _, _)).Times(0);
  EXPECT_CALL(observer_, OnUsbDeviceRemoved(_)).Times(0);
  notifier_.AddObserver(&observer_);
  notifier_.OnUdevMonitorFileDescriptorReadable();
}

TEST_F(UsbDeviceEventNotifierTest, OnUsbDeviceEventWithInvalidDeviceAddress) {
  auto device = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device, GetSysPath()).WillOnce(Return(kFakeUsbDevice1SysPath));
  EXPECT_CALL(*device, GetAction()).WillOnce(Return(kUdevActionAdd));
  EXPECT_CALL(*device, GetSysAttributeValue(_))
      .WillOnce(Return(kFakeUsbDevice1BusNumberString))
      .WillOnce(Return(""));

  auto monitor = std::make_unique<brillo::MockUdevMonitor>();
  EXPECT_CALL(*monitor, ReceiveDevice())
      .WillOnce(Return(ByMove(std::move(device))));
  notifier_.udev_monitor_ = std::move(monitor);

  EXPECT_CALL(observer_, OnUsbDeviceAdded(_, _, _, _, _)).Times(0);
  EXPECT_CALL(observer_, OnUsbDeviceRemoved(_)).Times(0);
  notifier_.AddObserver(&observer_);
  notifier_.OnUdevMonitorFileDescriptorReadable();
}

TEST_F(UsbDeviceEventNotifierTest, OnUsbDeviceEventWithInvalidVendorId) {
  auto device = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device, GetSysPath()).WillOnce(Return(kFakeUsbDevice1SysPath));
  EXPECT_CALL(*device, GetAction()).WillOnce(Return(kUdevActionAdd));
  EXPECT_CALL(*device, GetSysAttributeValue(_))
      .WillOnce(Return(kFakeUsbDevice1BusNumberString))
      .WillOnce(Return(kFakeUsbDevice1DeviceAddressString))
      .WillOnce(Return(""));

  auto monitor = std::make_unique<brillo::MockUdevMonitor>();
  EXPECT_CALL(*monitor, ReceiveDevice())
      .WillOnce(Return(ByMove(std::move(device))));
  notifier_.udev_monitor_ = std::move(monitor);

  EXPECT_CALL(observer_, OnUsbDeviceAdded(_, _, _, _, _)).Times(0);
  EXPECT_CALL(observer_, OnUsbDeviceRemoved(_)).Times(0);
  notifier_.AddObserver(&observer_);
  notifier_.OnUdevMonitorFileDescriptorReadable();
}

TEST_F(UsbDeviceEventNotifierTest, OnUsbDeviceEventWithInvalidProductId) {
  auto device = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device, GetSysPath()).WillOnce(Return(kFakeUsbDevice1SysPath));
  EXPECT_CALL(*device, GetAction()).WillOnce(Return(kUdevActionAdd));
  EXPECT_CALL(*device, GetSysAttributeValue(_))
      .WillOnce(Return(kFakeUsbDevice1BusNumberString))
      .WillOnce(Return(kFakeUsbDevice1DeviceAddressString))
      .WillOnce(Return(kFakeUsbDevice1VendorIdString))
      .WillOnce(Return(""));

  auto monitor = std::make_unique<brillo::MockUdevMonitor>();
  EXPECT_CALL(*monitor, ReceiveDevice())
      .WillOnce(Return(ByMove(std::move(device))));
  notifier_.udev_monitor_ = std::move(monitor);

  EXPECT_CALL(observer_, OnUsbDeviceAdded(_, _, _, _, _)).Times(0);
  EXPECT_CALL(observer_, OnUsbDeviceRemoved(_)).Times(0);
  notifier_.AddObserver(&observer_);
  notifier_.OnUdevMonitorFileDescriptorReadable();
}

TEST_F(UsbDeviceEventNotifierTest, ScanExistingDevices) {
  auto list_entry2 = std::make_unique<brillo::MockUdevListEntry>();
  EXPECT_CALL(*list_entry2, GetName()).WillOnce(Return(kFakeUsbDevice2SysPath));
  EXPECT_CALL(*list_entry2, GetNext()).WillOnce(Return(ByMove(nullptr)));

  auto list_entry1 = std::make_unique<brillo::MockUdevListEntry>();
  EXPECT_CALL(*list_entry1, GetName()).WillOnce(Return(kFakeUsbDevice1SysPath));
  EXPECT_CALL(*list_entry1, GetNext())
      .WillOnce(Return(ByMove(std::move(list_entry2))));

  auto enumerate = std::make_unique<brillo::MockUdevEnumerate>();
  EXPECT_CALL(*enumerate, AddMatchSubsystem(StrEq("usb")))
      .WillOnce(Return(true));
  EXPECT_CALL(*enumerate,
              AddMatchProperty(StrEq("DEVTYPE"), StrEq("usb_device")))
      .WillOnce(Return(true));
  EXPECT_CALL(*enumerate, ScanDevices()).WillOnce(Return(true));
  EXPECT_CALL(*enumerate, GetListEntry())
      .WillOnce(Return(ByMove(std::move(list_entry1))));

  EXPECT_CALL(udev_, CreateEnumerate())
      .WillOnce(Return(ByMove(std::move(enumerate))));

  auto device1 = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device1, GetSysAttributeValue(_))
      .WillOnce(Return(kFakeUsbDevice1BusNumberString))
      .WillOnce(Return(kFakeUsbDevice1DeviceAddressString))
      .WillOnce(Return(kFakeUsbDevice1VendorIdString))
      .WillOnce(Return(kFakeUsbDevice1ProductIdString));

  auto device2 = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device2, GetSysAttributeValue(_))
      .WillOnce(Return(kFakeUsbDevice2BusNumberString))
      .WillOnce(Return(kFakeUsbDevice2DeviceAddressString))
      .WillOnce(Return(kFakeUsbDevice2VendorIdString))
      .WillOnce(Return(kFakeUsbDevice2ProductIdString));

  EXPECT_CALL(udev_, CreateDeviceFromSysPath(_))
      .WillOnce(Return(ByMove(std::move(device1))))
      .WillOnce(Return(ByMove(std::move(device2))));

  InSequence sequence;
  EXPECT_CALL(
      observer_,
      OnUsbDeviceAdded(kFakeUsbDevice1SysPath, kFakeUsbDevice1BusNumber,
                       kFakeUsbDevice1DeviceAddress, kFakeUsbDevice1VendorId,
                       kFakeUsbDevice1ProductId));
  EXPECT_CALL(
      observer_,
      OnUsbDeviceAdded(kFakeUsbDevice2SysPath, kFakeUsbDevice2BusNumber,
                       kFakeUsbDevice2DeviceAddress, kFakeUsbDevice2VendorId,
                       kFakeUsbDevice2ProductId));
  EXPECT_CALL(observer_, OnUsbDeviceRemoved(_)).Times(0);

  notifier_.AddObserver(&observer_);
  notifier_.ScanExistingDevices();
}

}  // namespace brillo
