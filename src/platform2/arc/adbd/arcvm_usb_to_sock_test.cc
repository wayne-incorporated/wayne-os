/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "arc/adbd/arcvm_usb_to_sock.h"

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
std::unique_ptr<ArcVmUsbToSock> SetupChannel(const int sock_fd,
                                             const int output_fd) {
  std::unique_ptr<ArcVmUsbToSock> channel =
      std::make_unique<ArcVmUsbToSock>(sock_fd, output_fd);
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

// Writes the data in a vector to a fd and read the data back to check.
// return true if the content is identical between the write and read.
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

// Tests transfer.
void TestTransfer() {
  auto sock_pair = SetupSocketPair();
  ASSERT_TRUE(sock_pair.has_value());
  auto channel_fd = sock_pair->second.get();

  // A socket in the pair is bidirectional so we use the same socket
  // for both of input and output of the channel.
  auto channel = SetupChannel(channel_fd, channel_fd);
  ASSERT_NE(channel, nullptr);
  const size_t data_len = 100;
  std::vector<char> message(data_len, 0x5);
  EXPECT_TRUE(LoopCheck(sock_pair->first.get(), message));
  exit(EXIT_SUCCESS);
}

// TODO(crbug.com/1087440): Replace deathtest with conventional unit test
// APIs once we refactor the main code to test transfer only, without
// creating threads.

// We use death test in gtest to run test cases in another process.
// By doing so exiting channel won't terminate the gtest process
// prematurely when we still have other cases to run with it.
TEST(ArcVmUsbToSockDeathTest, TestTransfer) {
  EXPECT_EXIT(TestTransfer(), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}

}  // namespace
}  // namespace adbd
