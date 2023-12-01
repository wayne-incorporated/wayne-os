// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_config_descriptor.h"

#include <libusb.h>

#include <gtest/gtest.h>

#include "brillo/usb/usb_device.h"

namespace brillo {

TEST(UsbConfigDescriptorTest, TrivialGetters) {
  libusb_config_descriptor descriptor;
  descriptor.bLength = 9;
  descriptor.bDescriptorType = LIBUSB_DT_CONFIG;
  descriptor.wTotalLength = 300;
  descriptor.bNumInterfaces = 3;
  descriptor.bConfigurationValue = 1;
  descriptor.bmAttributes = 0xa0;
  descriptor.MaxPower = 2;

  base::WeakPtr<UsbDevice> device;
  UsbConfigDescriptor config_descriptor(device, &descriptor, false);
  EXPECT_EQ(9, config_descriptor.GetLength());
  EXPECT_EQ(LIBUSB_DT_CONFIG, config_descriptor.GetDescriptorType());
  EXPECT_EQ(300, config_descriptor.GetTotalLength());
  EXPECT_EQ(3, config_descriptor.GetNumInterfaces());
  EXPECT_EQ(1, config_descriptor.GetConfigurationValue());
  EXPECT_EQ(0xa0, config_descriptor.GetAttributes());
  EXPECT_EQ(2, config_descriptor.GetMaxPower());
}

}  // namespace brillo
