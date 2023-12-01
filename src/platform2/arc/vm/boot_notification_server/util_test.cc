// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/boot_notification_server/util.h"

#include <atomic>
#include <optional>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>

#include <base/command_line.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/rand_util.h>
#include <gtest/gtest.h>

namespace {

constexpr char kTestSocket[] = "/tmp/boot-notification-test.socket";
constexpr int kMsToNs = 1000000;

base::ScopedFD ConnectTo(sockaddr* addr) {
  base::ScopedFD fd(socket(addr->sa_family, SOCK_STREAM, 0));
  EXPECT_TRUE(fd.is_valid());

  EXPECT_EQ(HANDLE_EINTR(connect(fd.get(), addr, GetSockLen(addr->sa_family))),
            0);
  return fd;
}

}  // namespace

class BootNotificationServerTest : public testing::Test {
 public:
  BootNotificationServerTest() {
    strncpy(addr_.sun_path, kTestSocket, sizeof(addr_.sun_path) - 1);
  }

  void SetUp() override { unlink(kTestSocket); }
  void TearDown() override { unlink(kTestSocket); }

 protected:
  sockaddr* addr() { return reinterpret_cast<sockaddr*>(&addr_); }

  void sleep_ms(int ms) {
    timespec req{.tv_sec = 0, .tv_nsec = ms * kMsToNs};
    nanosleep(&req, nullptr);
  }

 private:
  sockaddr_un addr_{.sun_family = AF_UNIX};
};

// Checks that StartListening creates a valid socket on which to receive
// messages.
TEST_F(BootNotificationServerTest, StartListeningCreatesValidSocket) {
  base::ScopedFD listen_fd = StartListening(addr());
  ASSERT_TRUE(listen_fd.is_valid());

  // Test that the socket can be connected to.
  base::ScopedFD client_fd = ConnectTo(addr());
  ASSERT_TRUE(client_fd.is_valid());
}

// Checks that WaitForClientConnect() returns a valid fd when a client connects
// to the listening socket.
TEST_F(BootNotificationServerTest, WaitForClientConnect) {
  base::ScopedFD listen_fd = StartListening(addr());
  ASSERT_TRUE(listen_fd.is_valid());
  base::ScopedFD client_fd = ConnectTo(addr());
  ASSERT_TRUE(client_fd.is_valid());

  // WaitForClientConnect should return immediately since there is already a
  // pending connection on listen_fd.
  base::ScopedFD conn_fd = WaitForClientConnect(listen_fd.get());
  ASSERT_TRUE(conn_fd.is_valid());
}

// Checks that ReadFD correctly reads from an FD into a string.
TEST_F(BootNotificationServerTest, ReadFD) {
  int len = 50;
  std::string original = base::RandBytesAsString(len);

  // Create pipe
  int fds[2];
  ASSERT_EQ(pipe(fds), 0);
  base::ScopedFD read_fd(fds[0]);

  {
    // Send string on write end
    base::ScopedFD write_fd(fds[1]);
    ASSERT_EQ(HANDLE_EINTR(write(write_fd.get(), original.data(), len)), len);
  }

  // Read from read_fd and check that strings are identical.
  std::optional<std::string> result = ReadFD(read_fd.get());
  ASSERT_TRUE(result);
  EXPECT_EQ(result, original);
}

// Checks that ExtractCidValue reads the CID value from a string only when it
// is the first line in the string.
TEST_F(BootNotificationServerTest, ExtractCidValue) {
  std::string props = "ro.boot.prop1=value\nro.boot.prop2\n";
  std::string cid_line = "CID=123\n";
  std::string props_with_cid = cid_line + props;
  std::string props_wrong_cid = props + cid_line;

  std::string result_props;
  unsigned int result_cid;
  std::optional<std::pair<unsigned int, std::string>> result1 =
      ExtractCidValue(props_with_cid);
  ASSERT_TRUE(result1);
  std::tie(result_cid, result_props) = *result1;
  EXPECT_EQ(result_cid, 123);
  EXPECT_EQ(result_props, props);

  std::optional<std::pair<unsigned int, std::string>> result2 =
      ExtractCidValue(props);
  EXPECT_FALSE(result2);

  std::optional<std::pair<unsigned int, std::string>> result3 =
      ExtractCidValue(props_wrong_cid);
  EXPECT_FALSE(result3);
}

// TODO(wvk): Add a test for GetPeerCid once vsock loopback address is available
// (Linux 5.6).

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  logging::InitLogging(logging::LoggingSettings());
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
