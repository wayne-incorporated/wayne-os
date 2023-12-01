// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/usb/usb_device.h"

#include <string.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "lorgnette/test_util.h"
#include "lorgnette/usb/usb_device_fake.h"

namespace lorgnette {

namespace {

TEST(UsbDeviceTest, ExpectedDescription) {
  UsbDeviceFake device;

  libusb_device_descriptor device_desc = MakeMinimalDeviceDescriptor();
  device_desc.idVendor = 0x5678;
  device_desc.idProduct = 0xfedc;
  device.SetDeviceDescriptor(device_desc);
  device.Init();

  EXPECT_EQ(device.Description(), "5678:fedc");
}

TEST(UsbDeviceTest, NoIppUsbInvalidDeviceDescriptor) {
  UsbDeviceFake device;
  EXPECT_FALSE(device.SupportsIppUsb());
}

TEST(UsbDeviceTest, NoIppUsbWrongDeviceClass) {
  UsbDeviceFake device;

  libusb_device_descriptor device_desc = MakeMinimalDeviceDescriptor();
  device_desc.bDeviceClass = LIBUSB_CLASS_HUB;
  device.SetDeviceDescriptor(device_desc);
  device.Init();

  EXPECT_FALSE(device.SupportsIppUsb());
}

TEST(UsbDeviceTest, NoIppUsbNoPrinterInterface) {
  UsbDeviceFake device;

  libusb_device_descriptor device_desc = MakeMinimalDeviceDescriptor();
  device_desc.bDeviceClass = LIBUSB_CLASS_PER_INTERFACE;
  device_desc.bNumConfigurations = 1;
  device.SetDeviceDescriptor(device_desc);
  device.Init();

  // One config with no interfaces.
  libusb_config_descriptor descriptor;
  memset(&descriptor, 0, sizeof(descriptor));
  descriptor.bLength = sizeof(descriptor);
  descriptor.bDescriptorType = LIBUSB_DT_CONFIG;
  descriptor.wTotalLength = sizeof(descriptor);
  device.SetConfigDescriptors({descriptor});

  EXPECT_FALSE(device.SupportsIppUsb());
}

TEST(UsbDeviceTest, PrinterWithoutIppUsb) {
  UsbDeviceFake device;

  libusb_device_descriptor device_desc = MakeMinimalDeviceDescriptor();
  device_desc.bDeviceClass = LIBUSB_CLASS_PER_INTERFACE;
  device_desc.bNumConfigurations = 1;
  device.SetDeviceDescriptor(device_desc);
  device.Init();

  // One altsetting with a printer class but not the IPP-USB protocol.
  auto altsetting = MakeIppUsbInterfaceDescriptor();
  altsetting->bInterfaceProtocol = 0;

  // One interface containing the altsetting.
  auto interface = std::make_unique<libusb_interface>();
  interface->num_altsetting = 1;
  interface->altsetting = altsetting.get();

  // One config descriptor containing the interface.
  libusb_config_descriptor descriptor;
  memset(&descriptor, 0, sizeof(descriptor));
  descriptor.bLength = sizeof(descriptor);
  descriptor.bDescriptorType = LIBUSB_DT_CONFIG;
  descriptor.wTotalLength = sizeof(descriptor);
  descriptor.bNumInterfaces = 1;
  descriptor.interface = interface.get();

  device.SetConfigDescriptors({descriptor});

  EXPECT_FALSE(device.SupportsIppUsb());
}

TEST(UsbDeviceTest, PrinterWithIppUsb) {
  UsbDeviceFake device;

  libusb_device_descriptor device_desc = MakeMinimalDeviceDescriptor();
  device_desc.bDeviceClass = LIBUSB_CLASS_PER_INTERFACE;
  device_desc.bNumConfigurations = 1;
  device.SetDeviceDescriptor(device_desc);
  device.Init();

  // One altsetting with a printer class and the IPP-USB protocol.
  auto altsetting = MakeIppUsbInterfaceDescriptor();

  // One interface containing the altsetting.
  auto interface = std::make_unique<libusb_interface>();
  interface->num_altsetting = 1;
  interface->altsetting = altsetting.get();

  // One config descriptor containing the interface.
  libusb_config_descriptor descriptor;
  memset(&descriptor, 0, sizeof(descriptor));
  descriptor.bLength = sizeof(descriptor);
  descriptor.bDescriptorType = LIBUSB_DT_CONFIG;
  descriptor.wTotalLength = sizeof(descriptor);
  descriptor.bNumInterfaces = 1;
  descriptor.interface = interface.get();

  device.SetConfigDescriptors({descriptor});

  EXPECT_TRUE(device.SupportsIppUsb());
}

TEST(UsbDeviceTest, ScannerInfoMissingDescriptor) {
  UsbDeviceFake device;
  device.Init();

  EXPECT_EQ(device.IppUsbScannerInfo(), std::nullopt);
}

TEST(UsbDeviceTest, ScannerInfoMissingManufacturer) {
  UsbDeviceFake device;

  libusb_device_descriptor device_desc = MakeMinimalDeviceDescriptor();
  device_desc.iManufacturer = 1;
  device.SetDeviceDescriptor(device_desc);
  device.Init();

  EXPECT_EQ(device.IppUsbScannerInfo(), std::nullopt);
}

TEST(UsbDeviceTest, ScannerInfoMissingProduct) {
  UsbDeviceFake device;

  libusb_device_descriptor device_desc = MakeMinimalDeviceDescriptor();
  device_desc.iManufacturer = 1;
  device_desc.iProduct = 2;
  device.SetStringDescriptors({"", "GoogleTest"});
  device.SetDeviceDescriptor(device_desc);
  device.Init();

  EXPECT_EQ(device.IppUsbScannerInfo(), std::nullopt);
}

TEST(UsbDeviceTest, ScannerInfoDedupMfgrInModel) {
  UsbDeviceFake device;

  libusb_device_descriptor device_desc = MakeMinimalDeviceDescriptor();
  device_desc.iManufacturer = 1;
  device_desc.iProduct = 2;
  device.SetStringDescriptors({"", "GoogleTest", "GoogleTest Scanner 3000"});
  device.SetDeviceDescriptor(device_desc);
  device.Init();

  auto info = device.IppUsbScannerInfo();
  ASSERT_TRUE(info.has_value());
  EXPECT_EQ(info->name(),
            "ippusb:escl:GoogleTest Scanner 3000:1234_4321/eSCL/");
  EXPECT_EQ(info->manufacturer(), "GoogleTest");
  EXPECT_EQ(info->model(), "GoogleTest Scanner 3000");
}

TEST(UsbDeviceTest, ScannerInfoConcatModelWithoutMfgr) {
  UsbDeviceFake device;

  libusb_device_descriptor device_desc = MakeMinimalDeviceDescriptor();
  device_desc.iManufacturer = 1;
  device_desc.iProduct = 2;
  device.SetStringDescriptors({"", "GoogleTest", "Scanner 3000"});
  device.SetDeviceDescriptor(device_desc);
  device.Init();

  auto info = device.IppUsbScannerInfo();
  ASSERT_TRUE(info.has_value());
  EXPECT_EQ(info->name(),
            "ippusb:escl:GoogleTest Scanner 3000:1234_4321/eSCL/");
  EXPECT_EQ(info->manufacturer(), "GoogleTest");
  EXPECT_EQ(info->model(), "Scanner 3000");
}

}  // namespace

}  // namespace lorgnette
