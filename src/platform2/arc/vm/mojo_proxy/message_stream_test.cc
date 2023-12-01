// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/mojo_proxy/message_stream.h"

#include <sys/socket.h>

#include <tuple>
#include <utility>

#include <base/files/scoped_file.h>
#include <gtest/gtest.h>

#include "arc/vm/mojo_proxy/file_descriptor_util.h"
#include "arc/vm/mojo_proxy/message.pb.h"

namespace arc {
namespace {

TEST(MessageStreamTest, ReadWrite) {
  // Use a blocking socket pair instead of virtio-wl for testing.
  auto sockpair = CreateSocketPair(SOCK_STREAM);
  ASSERT_TRUE(sockpair.has_value());
  base::ScopedFD fd1;
  base::ScopedFD fd2;
  std::tie(fd1, fd2) = std::move(sockpair).value();

  arc_proxy::MojoMessage message;
  message.mutable_data()->set_handle(10);
  message.mutable_data()->set_blob("abcde");
  {
    MessageStream stream(std::move(fd1));
    ASSERT_TRUE(stream.Write(message, {}));
  }

  arc_proxy::MojoMessage read_message;
  ASSERT_TRUE(MessageStream(std::move(fd2)).Read(&read_message, nullptr));
  EXPECT_EQ(message.data().handle(), read_message.data().handle());
  EXPECT_EQ(message.data().blob(), read_message.data().blob());
}

}  // namespace
}  // namespace arc
