/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "arc/adbd/arcvm_sock_to_usb.h"

#include <sys/socket.h>
#include <sys/types.h>

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <gtest/gtest.h>

namespace adbd {
namespace {

std::unique_ptr<ArcVmSockToUsb> SetupChannel(const int sock_fd,
                                             const int output_fd) {
  std::unique_ptr<ArcVmSockToUsb> channel =
      std::make_unique<ArcVmSockToUsb>(sock_fd, output_fd);
  if (!channel->Start()) {
    LOG(ERROR) << "Failed to start channel for test";
    return nullptr;
  }
  return channel;
}

std::optional<std::pair<base::ScopedFD, base::ScopedFD>> SetupSocketPair() {
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == -1) {
    PLOG(ERROR) << "Failed to create socket pair for test";
    return std::nullopt;
  }
  return std::make_optional(
      std::make_pair(base::ScopedFD(fds[0]), base::ScopedFD(fds[1])));
}

bool SetPayloadLength(const size_t payload_len, std::vector<char>* header) {
  if (header == nullptr)
    return false;
  auto sz = header->size();
  if (sz < kAmessageDataLenOffset + 4)
    return false;
  for (int i = 0; i < 4; i++) {
    // Some parentheses in the next line are added for readability.
    (*header)[kAmessageDataLenOffset + i] = (payload_len >> (8 * i)) & 0xff;
  }
  return true;
}

// Writes the data in a vector to a fd and read the data back to check.
// Returns true if the content is identical between the write and read.
bool LoopCheck(int fd, const std::vector<char>& src) {
  auto sz = src.size();
  if (fd < 0 || !sz)
    return false;
  if (!base::WriteFileDescriptor(fd, base::StringPiece(src.data(), sz)))
    return false;
  std::vector<char> output(sz);
  if (!base::ReadFromFD(fd, output.data(), sz))
    return false;
  return src == output;
}

// Channel should send out message without waiting more data
// when the message has no payload (payload fields are zeros)
void TestHeaderOnly() {
  auto sock_pair = SetupSocketPair();
  ASSERT_TRUE(sock_pair.has_value());
  auto channel_fd = sock_pair->second.get();

  // A socket in the pair is bidirectional so we use the same socket
  // for both of input and output of the channel.
  auto channel = SetupChannel(channel_fd, channel_fd);
  ASSERT_NE(channel, nullptr);
  std::vector<char> header(kAmessageSize, 0x5);
  ASSERT_TRUE(SetPayloadLength(0, &header));
  EXPECT_TRUE(LoopCheck(sock_pair->first.get(), header));
  exit(EXIT_SUCCESS);
}

// TODO(crbug.com/1087440): Replace deathtest with conventional unit test
// APIs once we refactor the main code to test transfer only, without
// creating threads.

// We use death test in gtest to run test cases in another process.
// By doing so exiting channel won't terminate the gtest process
// prematurely when we still have other cases to run with it.
TEST(ArcVmSockToUsbDeathTest, TestHeaderOnly) {
  EXPECT_EXIT(TestHeaderOnly(), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

// Tests a message with maximum payload.
void TestMaxPayload() {
  auto sock_pair = SetupSocketPair();
  ASSERT_TRUE(sock_pair.has_value());
  auto channel_fd = sock_pair->second.get();

  // A socket in the pair is bidirectional so we use the same socket
  // for both of input and output of the channel.
  auto channel = SetupChannel(channel_fd, channel_fd);
  ASSERT_NE(channel, nullptr);
  size_t message_len = kAmessageSize + kAdbPayloadMaxSize;
  std::vector<char> message(message_len, 0x5);
  ASSERT_TRUE(SetPayloadLength(kAdbPayloadMaxSize, &message));
  EXPECT_TRUE(LoopCheck(sock_pair->first.get(), message));
  exit(EXIT_SUCCESS);
}

TEST(ArcVmSockToUsbDeathTest, TestMaxPayload) {
  EXPECT_EXIT(TestMaxPayload(), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

// Tests an invalid payload length. Channel should exit with error.
void TestInvalidPayloadLength() {
  auto sock_pair = SetupSocketPair();
  ASSERT_TRUE(sock_pair.has_value());
  auto channel_fd = sock_pair->second.get();

  // A socket in the pair is bidirectional so we use the same socket
  // for both of input and output of the channel.
  auto channel = SetupChannel(channel_fd, channel_fd);
  ASSERT_NE(channel, nullptr);
  size_t message_len = kAmessageSize;
  std::vector<char> message(message_len, 0x5);
  ASSERT_TRUE(SetPayloadLength(kAdbPayloadMaxSize + 1, &message));
  LoopCheck(sock_pair->first.get(), message);
  ASSERT_TRUE(false) << "Should not reach here.";
}

TEST(ArcVmSockToUsbDeathTest, TestInvalidPayloadLength) {
  EXPECT_EXIT(TestInvalidPayloadLength(),
              ::testing::ExitedWithCode(EXIT_FAILURE),
              "payload length is too big");
}

}  // namespace
}  // namespace adbd
