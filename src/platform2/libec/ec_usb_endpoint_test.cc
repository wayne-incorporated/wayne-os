// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libusb-1.0/libusb.h>

#include "libec/ec_usb_endpoint.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::SetArgReferee;

namespace ec {
namespace {

class MockLibusb : public LibusbWrapper {
 public:
  MockLibusb() {}
  ~MockLibusb() {}

  MOCK_METHOD(int, init, (libusb_context * *ctx), (override));
  MOCK_METHOD(void, exit, (libusb_context * ctx), (override));
  MOCK_METHOD(ssize_t,
              get_device_list,
              (libusb_context * ctx, libusb_device*** list),
              (override));
  MOCK_METHOD(int,
              get_device_descriptor,
              (libusb_device * dev, struct libusb_device_descriptor* desc),
              (override));
  MOCK_METHOD(void,
              free_device_list,
              (libusb_device * *list, int unref_devices),
              (override));
  MOCK_METHOD(int,
              open,
              (libusb_device * dev, libusb_device_handle** dev_handle),
              (override));
  MOCK_METHOD(void, close, (libusb_device_handle * dev_handle), (override));
  MOCK_METHOD(int,
              get_active_config_descriptor,
              (libusb_device * dev, struct libusb_config_descriptor** config),
              (override));
  MOCK_METHOD(void,
              free_config_descriptor,
              (struct libusb_config_descriptor * config),
              (override));
  MOCK_METHOD(int,
              claim_interface,
              (libusb_device_handle * dev_handle, int interface_number),
              (override));
  MOCK_METHOD(int,
              release_interface,
              (libusb_device_handle * dev_handle, int interface_number),
              (override));
};

class EcUsbEndpointTest : public ::testing::Test {
 protected:
  std::unique_ptr<MockLibusb> mock = std::make_unique<MockLibusb>();
  libusb_device* devs[2] = {
      reinterpret_cast<libusb_device*>(1),
      nullptr,
  };
  struct libusb_device_descriptor desc = {
      .idVendor = 0x18d1,
      .idProduct = 0x5022,
  };
  libusb_device_handle* handle = reinterpret_cast<libusb_device_handle*>(3);
  struct libusb_endpoint_descriptor ep = {
      .bEndpointAddress = 2,
      .wMaxPacketSize = 64,
  };
  struct libusb_interface_descriptor iface = {
      .bInterfaceNumber = 1,
      .bNumEndpoints = 1,
      .endpoint = &ep,
  };
  struct libusb_interface interface = {
      .altsetting = &iface,
      .num_altsetting = 1,
  };
  struct libusb_config_descriptor conf = {
      .bNumInterfaces = 1,
      .interface = &interface,
  };
};

TEST_F(EcUsbEndpointTest, Init_FailInInit) {
  EXPECT_CALL(*mock, init).WillOnce(Return(LIBUSB_ERROR_IO));
  EXPECT_CALL(*mock, exit).Times(0);

  EcUsbEndpoint uep(std::move(mock), /*max_retries=*/0);
  EXPECT_FALSE(uep.Init(0x18d1, 0x5022));
}

TEST_F(EcUsbEndpointTest, Init_FailInGetDeviceList) {
  EXPECT_CALL(*mock, init).WillOnce(Return(LIBUSB_SUCCESS));
  EXPECT_CALL(*mock, get_device_list).WillOnce(Return(LIBUSB_ERROR_IO));
  EXPECT_CALL(*mock, exit);

  EcUsbEndpoint uep(std::move(mock), /*max_retries=*/0);
  EXPECT_FALSE(uep.Init(0x18d1, 0x5022));
}

TEST_F(EcUsbEndpointTest, Init_CantFindDevice) {
  EXPECT_CALL(*mock, init).WillOnce(Return(LIBUSB_SUCCESS));
  EXPECT_CALL(*mock, get_device_list)
      .WillOnce(DoAll(SetArgPointee<1>(devs), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, get_device_descriptor).WillOnce(Return(LIBUSB_ERROR_IO));
  EXPECT_CALL(*mock, free_device_list).WillOnce(Return());
  EXPECT_CALL(*mock, exit).WillOnce(Return());

  EcUsbEndpoint uep(std::move(mock), /*max_retries=*/0);
  EXPECT_FALSE(uep.Init(0x18d1, 0x5022));
}

TEST_F(EcUsbEndpointTest, Init_FailInVid) {
  desc.idVendor = 0;

  EXPECT_CALL(*mock, init).WillOnce(Return(LIBUSB_SUCCESS));
  EXPECT_CALL(*mock, get_device_list)
      .WillOnce(DoAll(SetArgPointee<1>(devs), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, get_device_descriptor)
      .WillOnce(DoAll(SetArgPointee<1>(desc), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, free_device_list).WillOnce(Return());
  EXPECT_CALL(*mock, exit).WillOnce(Return());

  EcUsbEndpoint uep(std::move(mock), /*max_retries=*/0);
  EXPECT_FALSE(uep.Init(0x18d1, 0x5022));
}

TEST_F(EcUsbEndpointTest, Init_FailInPid) {
  desc.idProduct = 0;

  EXPECT_CALL(*mock, init).WillOnce(Return(LIBUSB_SUCCESS));
  EXPECT_CALL(*mock, get_device_list)
      .WillOnce(DoAll(SetArgPointee<1>(devs), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, get_device_descriptor)
      .WillOnce(DoAll(SetArgPointee<1>(desc), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, free_device_list).WillOnce(Return());
  EXPECT_CALL(*mock, exit).WillOnce(Return());

  EcUsbEndpoint uep(std::move(mock), /*max_retries=*/0);
  EXPECT_FALSE(uep.Init(0x18d1, 0x5022));
}

TEST_F(EcUsbEndpointTest, Init_FailInGetConfigDescriptor) {
  EXPECT_CALL(*mock, init).WillOnce(Return(LIBUSB_SUCCESS));
  EXPECT_CALL(*mock, get_device_list)
      .WillOnce(DoAll(SetArgPointee<1>(devs), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, get_device_descriptor)
      .WillOnce(DoAll(SetArgPointee<1>(desc), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, get_active_config_descriptor)
      .WillOnce(Return(LIBUSB_ERROR_IO));
  EXPECT_CALL(*mock, free_device_list).WillOnce(Return());
  EXPECT_CALL(*mock, exit).WillOnce(Return());

  EcUsbEndpoint uep(std::move(mock), /*max_retries=*/0);
  EXPECT_FALSE(uep.Init(0x18d1, 0x5022));
}

TEST_F(EcUsbEndpointTest, Init_BadMaxPacketSize) {
  ep.wMaxPacketSize = 0;

  EXPECT_CALL(*mock, init).WillOnce(Return(LIBUSB_SUCCESS));
  EXPECT_CALL(*mock, get_device_list)
      .WillOnce(DoAll(SetArgPointee<1>(devs), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, get_device_descriptor)
      .WillOnce(DoAll(SetArgPointee<1>(desc), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, get_active_config_descriptor)
      .WillOnce(DoAll(SetArgPointee<1>(&conf), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, free_config_descriptor).WillOnce(Return());
  EXPECT_CALL(*mock, free_device_list).WillOnce(Return());
  EXPECT_CALL(*mock, exit).WillOnce(Return());

  EcUsbEndpoint uep(std::move(mock), /*max_retries=*/0);
  EXPECT_FALSE(uep.Init(0x18d1, 0x5022));
}

TEST_F(EcUsbEndpointTest, Init_Success) {
  EXPECT_CALL(*mock, init).WillOnce(Return(LIBUSB_SUCCESS));
  EXPECT_CALL(*mock, get_device_list)
      .WillOnce(DoAll(SetArgPointee<1>(devs), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, get_device_descriptor)
      .WillOnce(DoAll(SetArgPointee<1>(desc), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, get_active_config_descriptor)
      .WillOnce(DoAll(SetArgPointee<1>(&conf), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, free_config_descriptor).WillOnce(Return());
  EXPECT_CALL(*mock, free_device_list).WillOnce(Return());
  EXPECT_CALL(*mock, exit).WillOnce(Return());

  EcUsbEndpoint uep(std::move(mock), /*max_retries=*/0);
  EXPECT_TRUE(uep.Init(0x18d1, 0x5022));
}

TEST_F(EcUsbEndpointTest, ClaimInterface_NotInitialized) {
  EcUsbEndpoint uep(std::move(mock), /*max_retries=*/0);
  EXPECT_FALSE(uep.ClaimInterface());
}

TEST_F(EcUsbEndpointTest, ClaimInterface_FailInOpen) {
  EXPECT_CALL(*mock, init).WillOnce(Return(LIBUSB_SUCCESS));
  EXPECT_CALL(*mock, get_device_list)
      .WillOnce(DoAll(SetArgPointee<1>(devs), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, get_device_descriptor)
      .WillOnce(DoAll(SetArgPointee<1>(desc), Return(LIBUSB_SUCCESS)));
  EXPECT_CALL(*mock, get_active_config_descriptor)
      .WillOnce(DoAll(SetArgPointee<1>(&conf), Return(LIBUSB_SUCCESS)));

  EXPECT_CALL(*mock, open).WillOnce(Return(LIBUSB_ERROR_IO));
  EXPECT_CALL(*mock, claim_interface).Times(0);

  EcUsbEndpoint uep(std::move(mock), /*max_retries=*/0);
  EXPECT_TRUE(uep.Init(0x18d1, 0x5022));

  EXPECT_FALSE(uep.ClaimInterface());
}

TEST_F(EcUsbEndpointTest, ReleaseInterface_NotInitialized) {
  EcUsbEndpoint uep(std::move(mock), /*max_retries=*/0);
  EXPECT_TRUE(uep.ReleaseInterface());
}

}  // namespace
}  // namespace ec
