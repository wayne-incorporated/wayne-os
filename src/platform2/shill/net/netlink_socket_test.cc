// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/netlink_socket.h"

#include <linux/netlink.h>

#include <algorithm>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/net/byte_string.h"
#include "shill/net/mock_sockets.h"
#include "shill/net/netlink_fd.h"
#include "shill/net/netlink_message.h"

using testing::_;
using testing::Invoke;
using testing::Return;
using testing::Test;

namespace shill {

const int kFakeFd = 99;

class NetlinkSocketTest : public Test {
 public:
  NetlinkSocketTest() = default;
  ~NetlinkSocketTest() override = default;

  void SetUp() override {
    mock_sockets_ = new MockSockets();
    netlink_socket_.sockets_.reset(mock_sockets_);
  }

  virtual void InitializeSocket(int fd) {
    EXPECT_CALL(*mock_sockets_,
                Socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_GENERIC))
        .WillOnce(Return(fd));
    EXPECT_CALL(*mock_sockets_, SetReceiveBuffer(fd, kNetlinkReceiveBufferSize))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock_sockets_, Bind(fd, _, sizeof(struct sockaddr_nl)))
        .WillOnce(Return(0));
    EXPECT_TRUE(netlink_socket_.Init());
  }

 protected:
  MockSockets* mock_sockets_;  // Owned by netlink_socket_.
  NetlinkSocket netlink_socket_;
};

class FakeSocketRead {
 public:
  explicit FakeSocketRead(const ByteString& next_read_string) {
    next_read_string_ = next_read_string;
  }
  // Copies |len| bytes of |next_read_string_| into |buf| and clears
  // |next_read_string_|.
  ssize_t FakeSuccessfulRead(int sockfd,
                             void* buf,
                             size_t len,
                             int flags,
                             struct sockaddr* src_addr,
                             socklen_t* addrlen) {
    if (!buf) {
      return -1;
    }
    int read_bytes = std::min(len, next_read_string_.GetLength());
    memcpy(buf, next_read_string_.GetConstData(), read_bytes);
    next_read_string_.Clear();
    return read_bytes;
  }

 private:
  ByteString next_read_string_;
};

TEST_F(NetlinkSocketTest, InitWorkingTest) {
  SetUp();
  InitializeSocket(kFakeFd);
  EXPECT_CALL(*mock_sockets_, Close(kFakeFd));
}

TEST_F(NetlinkSocketTest, InitBrokenSocketTest) {
  SetUp();

  const int kBadFd = -1;
  EXPECT_CALL(*mock_sockets_, Socket(PF_NETLINK, _, NETLINK_GENERIC))
      .WillOnce(Return(kBadFd));
  EXPECT_CALL(*mock_sockets_, SetReceiveBuffer(_, _)).Times(0);
  EXPECT_CALL(*mock_sockets_, Bind(_, _, _)).Times(0);
  EXPECT_FALSE(netlink_socket_.Init());
}

TEST_F(NetlinkSocketTest, InitBrokenBufferTest) {
  SetUp();

  EXPECT_CALL(*mock_sockets_, Socket(PF_NETLINK, _, NETLINK_GENERIC))
      .WillOnce(Return(kFakeFd));
  EXPECT_CALL(*mock_sockets_,
              SetReceiveBuffer(kFakeFd, kNetlinkReceiveBufferSize))
      .WillOnce(Return(-1));
  EXPECT_CALL(*mock_sockets_, Bind(kFakeFd, _, sizeof(struct sockaddr_nl)))
      .WillOnce(Return(0));
  EXPECT_TRUE(netlink_socket_.Init());

  // Destructor.
  EXPECT_CALL(*mock_sockets_, Close(kFakeFd));
}

TEST_F(NetlinkSocketTest, InitBrokenBindTest) {
  SetUp();

  EXPECT_CALL(*mock_sockets_, Socket(PF_NETLINK, _, NETLINK_GENERIC))
      .WillOnce(Return(kFakeFd));
  EXPECT_CALL(*mock_sockets_,
              SetReceiveBuffer(kFakeFd, kNetlinkReceiveBufferSize))
      .WillOnce(Return(0));
  EXPECT_CALL(*mock_sockets_, Bind(kFakeFd, _, sizeof(struct sockaddr_nl)))
      .WillOnce(Return(-1));
  EXPECT_CALL(*mock_sockets_, Close(kFakeFd)).WillOnce(Return(0));
  EXPECT_FALSE(netlink_socket_.Init());
}

TEST_F(NetlinkSocketTest, SendMessageTest) {
  SetUp();
  InitializeSocket(kFakeFd);

  std::string message_string = "This text is really arbitrary";
  ByteString message(message_string.c_str(), message_string.size());

  // Good Send.
  EXPECT_CALL(*mock_sockets_,
              Send(kFakeFd, message.GetConstData(), message.GetLength(), 0))
      .WillOnce(Return(message.GetLength()));
  EXPECT_TRUE(netlink_socket_.SendMessage(message));

  // Short Send.
  EXPECT_CALL(*mock_sockets_,
              Send(kFakeFd, message.GetConstData(), message.GetLength(), 0))
      .WillOnce(Return(message.GetLength() - 3));
  EXPECT_FALSE(netlink_socket_.SendMessage(message));

  // Bad Send.
  EXPECT_CALL(*mock_sockets_,
              Send(kFakeFd, message.GetConstData(), message.GetLength(), 0))
      .WillOnce(Return(-1));
  EXPECT_FALSE(netlink_socket_.SendMessage(message));

  // Destructor.
  EXPECT_CALL(*mock_sockets_, Close(kFakeFd));
}

TEST_F(NetlinkSocketTest, SequenceNumberTest) {
  SetUp();

  // Just a sequence number.
  const uint32_t arbitrary_number = 42;
  netlink_socket_.sequence_number_ = arbitrary_number;
  EXPECT_EQ(arbitrary_number + 1, netlink_socket_.GetSequenceNumber());

  // Make sure we don't go to |NetlinkMessage::kBroadcastSequenceNumber|.
  netlink_socket_.sequence_number_ = NetlinkMessage::kBroadcastSequenceNumber;
  EXPECT_NE(NetlinkMessage::kBroadcastSequenceNumber,
            netlink_socket_.GetSequenceNumber());
}

TEST_F(NetlinkSocketTest, GoodRecvMessageTest) {
  SetUp();
  InitializeSocket(kFakeFd);

  ByteString message;
  static const std::string next_read_string =
      "Random text may include things like 'freaking fracking foo'.";
  static const size_t read_size = next_read_string.size();
  ByteString expected_results(next_read_string.c_str(), read_size);
  FakeSocketRead fake_socket_read(expected_results);

  // Expect one call to get the size...
  EXPECT_CALL(*mock_sockets_,
              RecvFrom(kFakeFd, _, _, MSG_TRUNC | MSG_PEEK, _, _))
      .WillOnce(Return(read_size));

  // ...and expect a second call to get the data.
  EXPECT_CALL(*mock_sockets_, RecvFrom(kFakeFd, _, read_size, 0, _, _))
      .WillOnce(Invoke(&fake_socket_read, &FakeSocketRead::FakeSuccessfulRead));

  EXPECT_TRUE(netlink_socket_.RecvMessage(&message));
  EXPECT_TRUE(message.Equals(expected_results));

  // Destructor.
  EXPECT_CALL(*mock_sockets_, Close(kFakeFd));
}

TEST_F(NetlinkSocketTest, BadRecvMessageTest) {
  SetUp();
  InitializeSocket(kFakeFd);

  ByteString message;
  EXPECT_CALL(*mock_sockets_, RecvFrom(kFakeFd, _, _, _, _, _))
      .WillOnce(Return(-1));
  EXPECT_FALSE(netlink_socket_.RecvMessage(&message));

  EXPECT_CALL(*mock_sockets_, Close(kFakeFd));
}

}  // namespace shill.
