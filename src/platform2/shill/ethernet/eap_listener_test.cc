// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/eap_listener.h"

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <gtest/gtest.h>

#include "shill/ethernet/eap_protocol.h"
#include "shill/mock_log.h"
#include "shill/net/byte_string.h"
#include "shill/net/mock_io_handler_factory.h"
#include "shill/net/mock_sockets.h"

using testing::_;
using testing::HasSubstr;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;

namespace shill {

class EapListenerTest : public testing::Test {
 public:
  EapListenerTest() : listener_(kInterfaceIndex, kLinkName) {
    listener_.io_handler_factory_ = &io_handler_factory_;
  }

  ~EapListenerTest() override = default;

  void SetUp() override {
    auto sockets = std::make_unique<StrictMock<MockSockets>>();
    sockets_ = sockets.get();
    listener_.sockets_ = std::move(sockets);
    listener_.set_request_received_callback(base::BindRepeating(
        &EapListenerTest::ReceiveCallback, base::Unretained(this)));
  }

  void TearDown() override {
    if (GetSocket() == kSocketFD) {
      EXPECT_CALL(*sockets_, Close(kSocketFD));
      listener_.Stop();
    }
  }

  ssize_t SimulateRecvFrom(int sockfd,
                           void* buf,
                           size_t len,
                           int flags,
                           struct sockaddr* src_addr,
                           socklen_t* addrlen);

  MOCK_METHOD(void, ReceiveCallback, ());

 protected:
  static constexpr int kInterfaceIndex = 123;
  static constexpr char kLinkName[] = "eth0";
  static constexpr int kSocketFD = 456;
  static constexpr uint8_t kEapPacketPayload[] = {
      eap_protocol::kIeee8021xEapolVersion2,
      eap_protocol::kIIeee8021xTypeEapPacket,
      0x00,
      0x00,  // Payload length (should be 5, but unparsed by EapListener).
      eap_protocol::kEapCodeRequest,
      0x00,  // Identifier (unparsed).
      0x00,
      0x00,  // Packet length (should be 5, but unparsed by EapListener).
      0x01   // Request type: Identity (not parsed by EapListener).
  };

  bool CreateSocket() { return listener_.CreateSocket(); }
  int GetInterfaceIndex() { return listener_.interface_index_; }
  size_t GetMaxEapPacketLength() { return EapListener::kMaxEapPacketLength; }
  int GetSocket() { return listener_.socket_; }
  void StartListener() { StartListenerWithFD(kSocketFD); }
  void ReceiveRequest() { listener_.ReceiveRequest(kSocketFD); }
  void StartListenerWithFD(int fd);

  MockIOHandlerFactory io_handler_factory_;
  EapListener listener_;

  // Owned by EapListener, and tracked here only for mocks.
  MockSockets* sockets_;

  // Tests can assign this in order to set the data isreturned in our
  // mock implementation of Sockets::RecvFrom().
  ByteString recvfrom_reply_data_;
};

ssize_t EapListenerTest::SimulateRecvFrom(int sockfd,
                                          void* buf,
                                          size_t len,
                                          int flags,
                                          struct sockaddr* src_addr,
                                          socklen_t* addrlen) {
  // Mimic behavior of the real recvfrom -- copy no more than requested.
  int copy_length = std::min(recvfrom_reply_data_.GetLength(), len);
  memcpy(buf, recvfrom_reply_data_.GetConstData(), copy_length);
  return copy_length;
}

MATCHER_P(IsEapLinkAddress, interface_index, "") {
  const struct sockaddr_ll* socket_address =
      reinterpret_cast<const struct sockaddr_ll*>(arg);
  return socket_address->sll_family == AF_PACKET &&
         socket_address->sll_protocol == htons(ETH_P_PAE) &&
         socket_address->sll_ifindex == interface_index;
}

void EapListenerTest::StartListenerWithFD(int fd) {
  EXPECT_CALL(*sockets_,
              Socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_PAE)))
      .WillOnce(Return(fd));
  EXPECT_CALL(*sockets_, SetNonBlocking(fd)).WillOnce(Return(0));
  EXPECT_CALL(*sockets_,
              Bind(fd, IsEapLinkAddress(kInterfaceIndex), sizeof(sockaddr_ll)))
      .WillOnce(Return(0));
  EXPECT_CALL(io_handler_factory_,
              CreateIOReadyHandler(fd, IOHandler::kModeInput, _));
  EXPECT_TRUE(listener_.Start());
  EXPECT_EQ(fd, listener_.socket_);
}

TEST_F(EapListenerTest, Constructor) {
  EXPECT_EQ(kInterfaceIndex, GetInterfaceIndex());
  EXPECT_EQ(8, GetMaxEapPacketLength());
  EXPECT_EQ(-1, GetSocket());
}

TEST_F(EapListenerTest, SocketOpenFail) {
  ScopedMockLog log;
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("Could not create EAP listener socket")))
      .Times(1);

  EXPECT_CALL(*sockets_, Socket(PF_PACKET, _, htons(ETH_P_PAE)))
      .WillOnce(Return(-1));
  EXPECT_FALSE(CreateSocket());
}

TEST_F(EapListenerTest, SocketNonBlockingFail) {
  ScopedMockLog log;
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("Could not set socket to be non-blocking")))
      .Times(1);

  EXPECT_CALL(*sockets_, Socket(_, _, _)).WillOnce(Return(kSocketFD));
  EXPECT_CALL(*sockets_, SetNonBlocking(kSocketFD)).WillOnce(Return(-1));
  EXPECT_FALSE(CreateSocket());
}

TEST_F(EapListenerTest, SocketBindFail) {
  ScopedMockLog log;
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("Could not bind socket to interface")))
      .Times(1);

  EXPECT_CALL(*sockets_, Socket(_, _, _)).WillOnce(Return(kSocketFD));
  EXPECT_CALL(*sockets_, SetNonBlocking(kSocketFD)).WillOnce(Return(0));
  EXPECT_CALL(*sockets_, Bind(kSocketFD, _, _)).WillOnce(Return(-1));
  EXPECT_FALSE(CreateSocket());
}

TEST_F(EapListenerTest, StartSuccess) {
  StartListener();
}

TEST_F(EapListenerTest, StartMultipleTimes) {
  const int kFirstSocketFD = kSocketFD + 1;
  StartListenerWithFD(kFirstSocketFD);
  EXPECT_CALL(*sockets_, Close(kFirstSocketFD));
  StartListener();
}

TEST_F(EapListenerTest, Stop) {
  StartListener();
  EXPECT_EQ(kSocketFD, GetSocket());
  EXPECT_CALL(*sockets_, Close(kSocketFD));
  listener_.Stop();
  EXPECT_EQ(-1, GetSocket());
}

TEST_F(EapListenerTest, ReceiveFail) {
  StartListener();
  EXPECT_CALL(*sockets_,
              RecvFrom(kSocketFD, _, GetMaxEapPacketLength(), 0, _, _))
      .WillOnce(Return(-1));
  EXPECT_CALL(*this, ReceiveCallback()).Times(0);
  EXPECT_CALL(*sockets_, Close(kSocketFD));

  ScopedMockLog log;
  // RecvFrom returns an error.
  EXPECT_CALL(
      log, Log(logging::LOGGING_ERROR, _, HasSubstr("Socket recvfrom failed")))
      .Times(1);
  ReceiveRequest();
}

TEST_F(EapListenerTest, ReceiveEmpty) {
  StartListener();
  EXPECT_CALL(*sockets_,
              RecvFrom(kSocketFD, _, GetMaxEapPacketLength(), 0, _, _))
      .WillOnce(Return(0));
  EXPECT_CALL(*this, ReceiveCallback()).Times(0);
  ReceiveRequest();
}

TEST_F(EapListenerTest, ReceiveShort) {
  StartListener();
  recvfrom_reply_data_ =
      ByteString(kEapPacketPayload, GetMaxEapPacketLength() - 1);
  EXPECT_CALL(*sockets_,
              RecvFrom(kSocketFD, _, GetMaxEapPacketLength(), 0, _, _))
      .WillOnce(Invoke(this, &EapListenerTest::SimulateRecvFrom));
  EXPECT_CALL(*this, ReceiveCallback()).Times(0);
  ScopedMockLog log;
  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _,
                       HasSubstr("Short EAP packet received")))
      .Times(1);
  ReceiveRequest();
}

TEST_F(EapListenerTest, ReceiveInvalid) {
  StartListener();
  // We're partially initializing this field, just making sure at least one
  // part of it is incorrect.
  uint8_t bad_payload[sizeof(kEapPacketPayload)] = {
      eap_protocol::kIeee8021xEapolVersion1 - 1};
  recvfrom_reply_data_ = ByteString(bad_payload, sizeof(bad_payload));
  EXPECT_CALL(*sockets_,
              RecvFrom(kSocketFD, _, GetMaxEapPacketLength(), 0, _, _))
      .WillOnce(Invoke(this, &EapListenerTest::SimulateRecvFrom));
  EXPECT_CALL(*this, ReceiveCallback()).Times(0);
  ScopedMockLog log;
  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _,
                       HasSubstr("Packet is not a valid EAP request")))
      .Times(1);
  ReceiveRequest();
}

TEST_F(EapListenerTest, ReceiveSuccess) {
  StartListener();
  recvfrom_reply_data_ =
      ByteString(kEapPacketPayload, sizeof(kEapPacketPayload));
  EXPECT_CALL(*sockets_,
              RecvFrom(kSocketFD, _, GetMaxEapPacketLength(), 0, _, _))
      .WillOnce(Invoke(this, &EapListenerTest::SimulateRecvFrom));
  EXPECT_CALL(*this, ReceiveCallback()).Times(1);
  ReceiveRequest();
}

}  // namespace shill
