// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/vsh/utils.h"

#include <base/files/file_util.h>
#include <gtest/gtest.h>
#include <vm_protos/proto_bindings/vsh.pb.h>

namespace vm_tools {
namespace vsh {

TEST(VshTest, SendAndRecvGuestMessage) {
  constexpr char msg[] = "GuestMessage";
  int pipe_fds[2];

  ASSERT_TRUE(base::CreateLocalNonBlockingPipe(pipe_fds));
  base::ScopedFD fd_read(pipe_fds[0]);
  base::ScopedFD fd_write(pipe_fds[1]);

  GuestMessage sent;
  auto sent_data = sent.mutable_data_message();
  sent_data->set_stream(STDIN_STREAM);
  sent_data->set_data(msg, sizeof(msg) - 1);
  ASSERT_TRUE(SendMessage(fd_write.get(), sent));

  GuestMessage received;
  ASSERT_TRUE(RecvMessage(fd_read.get(), &received));

  auto received_data = received.data_message();
  EXPECT_EQ(received_data.stream(), STDIN_STREAM);
  EXPECT_EQ(received_data.data(), msg);
}

TEST(VshTest, SendAndRecvHostMessage) {
  constexpr char msg[] = "HostMessage";
  int pipe_fds[2];

  ASSERT_TRUE(base::CreateLocalNonBlockingPipe(pipe_fds));
  base::ScopedFD fd_read(pipe_fds[0]);
  base::ScopedFD fd_write(pipe_fds[1]);

  HostMessage sent;
  auto sent_data = sent.mutable_data_message();
  sent_data->set_stream(STDOUT_STREAM);
  sent_data->set_data(msg, sizeof(msg) - 1);
  ASSERT_TRUE(SendMessage(fd_write.get(), sent));

  HostMessage received;
  ASSERT_TRUE(RecvMessage(fd_read.get(), &received));

  auto received_data = received.data_message();
  EXPECT_EQ(received_data.stream(), STDOUT_STREAM);
  EXPECT_EQ(received_data.data(), msg);
}

TEST(VshTest, WriteKernelLog) {
  std::string msg("log message");
  int pipe_fds[2];

  ASSERT_TRUE(base::CreateLocalNonBlockingPipe(pipe_fds));
  base::ScopedFD fd_read(pipe_fds[0]);
  base::ScopedFD fd_write(pipe_fds[1]);

  ASSERT_TRUE(WriteKernelLogToFd(fd_write.get(), logging::LOGGING_INFO,
                                 "utils_test: ", msg, 0));

  char buf[1024];
  ssize_t read_size = read(fd_read.get(), buf, sizeof(buf));
  ASSERT_GT(read_size, 0);
  ASSERT_LT(read_size, 1024);
  buf[read_size] = '\0';
  EXPECT_STREQ(buf, "<6>utils_test: log message");
}

}  // namespace vsh
}  // namespace vm_tools
