// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_device_descriptor.h"

#include <libusb.h>

#include <gtest/gtest.h>

#include "brillo/usb/usb_device.h"

namespace brillo {

TEST(UsbDeviceDescriptorTest, TrivialGetters) {
  libusb_device_descriptor descriptor;
  descriptor.bLength = 18;
  descriptor.bDescriptorType = LIBUSB_DT_DEVICE;
  descriptor.bcdUSB = 200;
  descriptor.bDeviceClass = 0x02;
  descriptor.bDeviceSubClass = 0x03;
  descriptor.bDeviceProtocol = 0x04;
  descriptor.bMaxPacketSize0 = 128;
  descriptor.idVendor = 0x1234;
  descriptor.idProduct = 0xabcd;
  descriptor.bcdDevice = 567;
  descriptor.bNumConfigurations = 2;

  base::WeakPtr<UsbDevice> device;
  UsbDeviceDescriptor device_descriptor(device, &descriptor);
  EXPECT_EQ(18, device_descriptor.GetLength());
  EXPECT_EQ(LIBUSB_DT_DEVICE, device_descriptor.GetDescriptorType());
  EXPECT_EQ(0x02, device_descriptor.GetDeviceClass());
  EXPECT_EQ(0x03, device_descriptor.GetDeviceSubclass());
  EXPECT_EQ(0x04, device_descriptor.GetDeviceProtocol());
  EXPECT_EQ(128, device_descriptor.GetMaxPacketSize0());
  EXPECT_EQ(0x1234, device_descriptor.GetVendorId());
  EXPECT_EQ(0xabcd, device_descriptor.GetProductId());
  EXPECT_EQ(2, device_descriptor.GetNumConfigurations());
}

}  // namespace brillo
