// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_interface_descriptor.h"

#include <libusb.h>

#include <gtest/gtest.h>

#include "brillo/usb/usb_device.h"

namespace brillo {

TEST(UsbInterfaceDescriptorTest, TrivialGetters) {
  libusb_interface_descriptor descriptor;
  descriptor.bLength = 9;
  descriptor.bDescriptorType = LIBUSB_DT_INTERFACE;
  descriptor.bInterfaceNumber = 1;
  descriptor.bNumEndpoints = 5;
  descriptor.bInterfaceClass = 0x02;
  descriptor.bInterfaceSubClass = 0x03;
  descriptor.bInterfaceProtocol = 0x04;

  base::WeakPtr<UsbDevice> device;
  UsbInterfaceDescriptor interface_descriptor(device, &descriptor);
  EXPECT_EQ(9, interface_descriptor.GetLength());
  EXPECT_EQ(LIBUSB_DT_INTERFACE, interface_descriptor.GetDescriptorType());
  EXPECT_EQ(1, interface_descriptor.GetInterfaceNumber());
  EXPECT_EQ(5, interface_descriptor.GetNumEndpoints());
  EXPECT_EQ(0x02, interface_descriptor.GetInterfaceClass());
  EXPECT_EQ(0x03, interface_descriptor.GetInterfaceSubclass());
  EXPECT_EQ(0x04, interface_descriptor.GetInterfaceProtocol());
}

}  // namespace brillo
