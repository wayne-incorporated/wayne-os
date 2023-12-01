// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/mojo_proxy/file_descriptor_util.h"

#include <errno.h>

#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace arc {
namespace {

class FileDescriptorUtilSocketTest : public testing::Test {
 public:
  FileDescriptorUtilSocketTest() = default;
  FileDescriptorUtilSocketTest(const FileDescriptorUtilSocketTest&) = delete;
  FileDescriptorUtilSocketTest& operator=(const FileDescriptorUtilSocketTest&) =
      delete;

  ~FileDescriptorUtilSocketTest() override = default;

 protected:
  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  void TearDown() override { EXPECT_TRUE(temp_dir_.Delete()); }

  const base::FilePath& temp_dir() const { return temp_dir_.GetPath(); }

 private:
  base::ScopedTempDir temp_dir_;
};

// Checks the common scenario about using unix domain socket; create a socket,
// connect to it, accept the connection, then send a message between them.
TEST_F(FileDescriptorUtilSocketTest, UnixDomainSocket) {
  const base::FilePath path = temp_dir().Append("test.sock");
  auto socket = CreateUnixDomainSocket(path);
  std::pair<int, base::ScopedFD> errno_fd_pair = ConnectUnixDomainSocket(path);
  ASSERT_EQ(0, errno_fd_pair.first);
  auto accepted = AcceptSocket(socket.get());
  auto connected = std::move(errno_fd_pair.second);
  // Now |accepted| and |connected| should be connected each other.
  // Try to exchange some messages to make sure.
  constexpr char kTestData[] = "test_data";
  ASSERT_EQ(Sendmsg(accepted.get(), kTestData, sizeof(kTestData), {}),
            sizeof(kTestData));

  std::vector<base::ScopedFD> fds;
  char buf[256];
  ASSERT_EQ(sizeof(kTestData),
            Recvmsg(connected.get(), buf, sizeof(buf), &fds));
  EXPECT_STREQ("test_data", buf);
}

// Makes sure the errno from connect(2) is returned to the caller.
TEST_F(FileDescriptorUtilSocketTest, NoUnixDomainSocket) {
  const base::FilePath path = temp_dir().Append("test.sock");
  // Try to connect non-exist socket file.
  std::pair<int, base::ScopedFD> errno_fd_pair = ConnectUnixDomainSocket(path);
  // Make sure errno is properly returned.
  EXPECT_EQ(ENOENT, errno_fd_pair.first);
}

}  // namespace
}  // namespace arc
