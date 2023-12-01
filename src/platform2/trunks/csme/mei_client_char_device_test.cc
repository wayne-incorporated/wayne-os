// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/csme/mei_client_char_device.h"

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/logging.h>

#include <libhwsec-foundation/syscaller/mock_syscaller.h>

namespace trunks {
namespace csme {

namespace {

constexpr char kFakeMeiPath[] = "mei path";
constexpr uuid_le kFakeGuid = UUID_LE(
    0x88888888, 0x8888, 0x8888, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88);
constexpr int kFakeFd = 0xfd;
constexpr int kFakeMaxMsgLength = 5120;
constexpr char kFakeMessage[] = "fake message";
constexpr int kFakeMessageLength = sizeof(kFakeMessage) - 1;

using testing::_;
using testing::AtMost;
using testing::DoAll;
using testing::Return;
using testing::StrictMock;
using testing::WithArg;

}  // namespace

class MeiClientCharDeviceTest : public testing::Test {
 public:
  MeiClientCharDeviceTest() {
    EXPECT_CALL(mock_syscaller_, Close(kFakeFd))
        .Times(AtMost(1))
        .WillRepeatedly(Return(0));
  }
  ~MeiClientCharDeviceTest() override = default;

 protected:
  void InitializeMeiClient() {
    EXPECT_CALL(mock_syscaller_, Open(_, _)).WillOnce(Return(kFakeFd));
    EXPECT_CALL(mock_syscaller_, Ioctl(kFakeFd, IOCTL_MEI_CONNECT_CLIENT, _))
        .WillOnce(DoAll(WithArg<2>([](struct mei_connect_client_data* data) {
                          data->out_client_properties.max_msg_length =
                              kFakeMaxMsgLength;
                        }),
                        Return(0)));
    ASSERT_TRUE(client_.Initialize());
  }
  StrictMock<hwsec_foundation::MockSyscaller> mock_syscaller_;
  MeiClientCharDevice client_{kFakeMeiPath, kFakeGuid, &mock_syscaller_};
};

TEST_F(MeiClientCharDeviceTest, InitializeSuccess) {
  EXPECT_CALL(mock_syscaller_, Open(_, _)).WillOnce(Return(kFakeFd));
  EXPECT_CALL(mock_syscaller_, Ioctl(kFakeFd, IOCTL_MEI_CONNECT_CLIENT, _))
      .WillOnce(DoAll(WithArg<2>([](struct mei_connect_client_data* data) {
                        data->out_client_properties.max_msg_length =
                            kFakeMaxMsgLength;
                      }),
                      Return(0)));
  EXPECT_TRUE(client_.Initialize());
}

TEST_F(MeiClientCharDeviceTest, InitializeOpenFailure) {
  EXPECT_CALL(mock_syscaller_, Open(_, _)).WillOnce(Return(-1));
  EXPECT_FALSE(client_.Initialize());
}

TEST_F(MeiClientCharDeviceTest, InitializeIoctlFailure) {
  EXPECT_CALL(mock_syscaller_, Open(_, _)).WillOnce(Return(kFakeFd));
  EXPECT_CALL(mock_syscaller_, Ioctl(kFakeFd, IOCTL_MEI_CONNECT_CLIENT, _))
      .WillOnce(Return(-1));
  // In this case, the fd is opened, and in turn expected to be close.
  EXPECT_CALL(mock_syscaller_, Close(kFakeFd));
  EXPECT_FALSE(client_.Initialize());
}

TEST_F(MeiClientCharDeviceTest, ReceiveInitializeFailure) {
  std::string data;
  EXPECT_CALL(mock_syscaller_, Open(_, _)).WillOnce(Return(-1));
  EXPECT_FALSE(client_.Receive(&data));
}

TEST_F(MeiClientCharDeviceTest, SendInitializeFailure) {
  std::string data;
  EXPECT_CALL(mock_syscaller_, Open(_, _)).WillOnce(Return(-1));
  EXPECT_FALSE(client_.Send(data, /*wait_for_response_ready=*/true));
}

TEST_F(MeiClientCharDeviceTest, ReceiveSuccess) {
  std::string data;
  InitializeMeiClient();
  EXPECT_CALL(mock_syscaller_, Read(kFakeFd, _, kFakeMaxMsgLength))
      .WillOnce(DoAll(WithArg<1>([](void* p) {
                        memcpy(p, kFakeMessage, kFakeMessageLength);
                      }),
                      Return(kFakeMessageLength)));
  EXPECT_TRUE(client_.Receive(&data));
  EXPECT_EQ(data, std::string(kFakeMessage));
}

TEST_F(MeiClientCharDeviceTest, ReceiveReadFailure) {
  std::string data;
  InitializeMeiClient();
  EXPECT_CALL(mock_syscaller_, Read(kFakeFd, _, kFakeMaxMsgLength))
      .WillOnce(Return(-1));
  EXPECT_FALSE(client_.Receive(&data));
}

TEST_F(MeiClientCharDeviceTest, SendSuccess) {
  InitializeMeiClient();
  EXPECT_CALL(mock_syscaller_, Write(kFakeFd, _, kFakeMessageLength))
      .WillOnce(Return(kFakeMessageLength));
  EXPECT_CALL(mock_syscaller_, Select(kFakeFd + 1, _, nullptr, nullptr, _))
      .WillOnce(Return(1));
  EXPECT_TRUE(client_.Send(kFakeMessage, /*wait_for_response_ready=*/true));
}

TEST_F(MeiClientCharDeviceTest, SendSuccessNoWaitForResponseReady) {
  InitializeMeiClient();
  EXPECT_CALL(mock_syscaller_, Write(kFakeFd, _, kFakeMessageLength))
      .WillOnce(Return(kFakeMessageLength));
  // `Select()` shouldn't be called; `StrictMock` will verify it.

  EXPECT_TRUE(client_.Send(kFakeMessage, /*wait_for_response_ready=*/false));
}

TEST_F(MeiClientCharDeviceTest, SendBadWriteSize) {
  InitializeMeiClient();
  // Either the value greater or less than than the expected written size should
  // fail the operation.
  EXPECT_CALL(mock_syscaller_, Write(kFakeFd, _, kFakeMessageLength))
      .WillOnce(Return(kFakeMessageLength + 1))
      .WillOnce(Return(kFakeMessageLength - 1));
  EXPECT_FALSE(client_.Send(kFakeMessage, /*wait_for_response_ready=*/true));
  EXPECT_FALSE(client_.Send(kFakeMessage, /*wait_for_response_ready=*/true));
}

TEST_F(MeiClientCharDeviceTest, SendSelectTimeout) {
  InitializeMeiClient();
  EXPECT_CALL(mock_syscaller_, Write(kFakeFd, _, kFakeMessageLength))
      .WillOnce(Return(kFakeMessageLength));
  EXPECT_CALL(mock_syscaller_, Select(kFakeFd + 1, _, nullptr, nullptr, _))
      .WillOnce(Return(0));
  EXPECT_FALSE(client_.Send(kFakeMessage, /*wait_for_response_ready=*/true));
}

TEST_F(MeiClientCharDeviceTest, SendSelectError) {
  InitializeMeiClient();
  EXPECT_CALL(mock_syscaller_, Write(kFakeFd, _, kFakeMessageLength))
      .WillOnce(Return(kFakeMessageLength));
  EXPECT_CALL(mock_syscaller_, Select(kFakeFd + 1, _, nullptr, nullptr, _))
      .WillOnce(Return(-1));
  EXPECT_FALSE(client_.Send(kFakeMessage, /*wait_for_response_ready=*/true));
}

}  // namespace csme
}  // namespace trunks
