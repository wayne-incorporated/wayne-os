// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_endpoint_descriptor.h"

#include <libusb.h>

#include <gtest/gtest.h>

namespace brillo {

TEST(UsbEndpointDescriptorTest, TrivialGetters) {
  libusb_endpoint_descriptor descriptor;
  descriptor.bLength = 7;
  descriptor.bDescriptorType = LIBUSB_DT_ENDPOINT;
  descriptor.bEndpointAddress = 0x81;
  descriptor.bmAttributes = 0x3;
  descriptor.wMaxPacketSize = 64;
  descriptor.bInterval = 32;

  UsbEndpointDescriptor endpoint_descriptor(&descriptor);
  EXPECT_EQ(7, endpoint_descriptor.GetLength());
  EXPECT_EQ(LIBUSB_DT_ENDPOINT, endpoint_descriptor.GetDescriptorType());
  EXPECT_EQ(0x81, endpoint_descriptor.GetEndpointAddress());
  EXPECT_EQ(1, endpoint_descriptor.GetEndpointNumber());
  EXPECT_EQ(0x3, endpoint_descriptor.GetAttributes());
  EXPECT_EQ(64, endpoint_descriptor.GetMaxPacketSize());
  EXPECT_EQ(32, endpoint_descriptor.GetInterval());
}

TEST(UsbEndpointDescriptorTest, GetDirection) {
  {
    libusb_endpoint_descriptor descriptor;
    descriptor.bEndpointAddress = LIBUSB_ENDPOINT_IN | 0x1;

    UsbEndpointDescriptor endpoint_descriptor(&descriptor);
    EXPECT_EQ(kUsbDirectionIn, endpoint_descriptor.GetDirection());
  }
  {
    libusb_endpoint_descriptor descriptor;
    descriptor.bEndpointAddress = LIBUSB_ENDPOINT_OUT | 0x1;

    UsbEndpointDescriptor endpoint_descriptor(&descriptor);
    EXPECT_EQ(kUsbDirectionOut, endpoint_descriptor.GetDirection());
  }
}

TEST(UsbEndpointDescriptorTest, GetTransferType) {
  {
    libusb_endpoint_descriptor descriptor;
    descriptor.bmAttributes = LIBUSB_TRANSFER_TYPE_CONTROL;

    UsbEndpointDescriptor endpoint_descriptor(&descriptor);
    EXPECT_EQ(kUsbTransferTypeControl, endpoint_descriptor.GetTransferType());
  }
  {
    libusb_endpoint_descriptor descriptor;
    descriptor.bmAttributes = LIBUSB_TRANSFER_TYPE_ISOCHRONOUS;

    UsbEndpointDescriptor endpoint_descriptor(&descriptor);
    EXPECT_EQ(kUsbTransferTypeIsochronous,
              endpoint_descriptor.GetTransferType());
  }
  {
    libusb_endpoint_descriptor descriptor;
    descriptor.bmAttributes = LIBUSB_TRANSFER_TYPE_BULK;

    UsbEndpointDescriptor endpoint_descriptor(&descriptor);
    EXPECT_EQ(kUsbTransferTypeBulk, endpoint_descriptor.GetTransferType());
  }
  {
    libusb_endpoint_descriptor descriptor;
    descriptor.bmAttributes = LIBUSB_TRANSFER_TYPE_INTERRUPT;

    UsbEndpointDescriptor endpoint_descriptor(&descriptor);
    EXPECT_EQ(kUsbTransferTypeInterrupt, endpoint_descriptor.GetTransferType());
  }
}

}  // namespace brillo
