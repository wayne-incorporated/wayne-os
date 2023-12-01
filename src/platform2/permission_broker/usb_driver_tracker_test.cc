// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/usb_driver_tracker.h"

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/containers/contains.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/test/task_environment.h>

using ::testing::DoAll;
using ::testing::Return;

namespace permission_broker {

namespace {

static constexpr int kMaxNumClients = 2;
static constexpr uint8_t kIface0 = 0;
static constexpr uint8_t kIface1 = 1;
static constexpr uint8_t kIface2 = 2;
static constexpr int kClient0 = 0;
static constexpr int kClient1 = 1;

ACTION_P(QuitRunLoop, run_loop) {
  run_loop->Quit();
}

}  // namespace

class MockUsbDriverTracker : public UsbDriverTracker {
 public:
  MockUsbDriverTracker() {
    ON_CALL(*this, WatchLifelineFd)
        .WillByDefault([this](const std::string& client_id, int lifeline_fd) {
          // The injection for WatchLifelineFd is not only for mocking return
          // null case, but also to register HandleClosedFd with mock object so
          // mocked methods can be called when HandleClosedFd is invoked when
          // lifeline_fd closes.
          return base::FileDescriptorWatcher::WatchReadable(
              lifeline_fd,
              base::BindRepeating(&UsbDriverTracker::HandleClosedFd,
                                  weak_ptr_factory_.GetWeakPtr(), client_id));
        });
    ON_CALL(*this, ConnectInterface).WillByDefault(Return(true));
    ON_CALL(*this, DisconnectInterface).WillByDefault(Return(true));
  }
  MockUsbDriverTracker(const MockUsbDriverTracker&) = delete;
  MockUsbDriverTracker& operator=(const MockUsbDriverTracker&) = delete;
  ~MockUsbDriverTracker() override = default;

  MOCK_METHOD(std::unique_ptr<base::FileDescriptorWatcher::Controller>,
              WatchLifelineFd,
              (const std::string&, int),
              (override));
  MOCK_METHOD(bool, DisconnectInterface, (int, uint8_t), (override));
  MOCK_METHOD(bool, ConnectInterface, (int, uint8_t), (override));
};

class UsbDriverTrackerTest : public testing::Test {
 public:
  UsbDriverTrackerTest() = default;
  UsbDriverTrackerTest(const UsbDriverTrackerTest&) = delete;
  UsbDriverTrackerTest& operator=(const UsbDriverTrackerTest&) = delete;
  ~UsbDriverTrackerTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(CreateTemporaryFile(&temp_file_path_));
    for (int client = 0; client < kMaxNumClients; client++) {
      ASSERT_TRUE(base::CreatePipe(/*read_fd*/ &pipe_fds_[client][0],
                                   /*write_fd*/ &pipe_fds_[client][1],
                                   /*non_blocking*/ true));
    }
  }

  void TearDown() override {
    testing::Mock::VerifyAndClearExpectations(&usb_driver_tracker_);
    // Doing this to use mock CleanUpTracking to avoid warning message of
    // connect ioctl() failure from the destructor when there is left record in
    // the end of the test.
    usb_driver_tracker_.CleanUpTracking();
  }

  std::string SetupClient(int client,
                          const base::FilePath& path,
                          std::vector<uint8_t>& ifaces) {
    EXPECT_LT(client, kMaxNumClients);
    return SetupClientWithLifelineFd(pipe_fds_[client][0].get(), path, ifaces);
  }

  std::string SetupClientWithLifelineFd(int lifeline_fd,
                                        const base::FilePath& path,
                                        std::vector<uint8_t>& ifaces) {
    EXPECT_CALL(usb_driver_tracker_, WatchLifelineFd).Times(1);

    auto maybe_client_id =
        usb_driver_tracker_.RegisterClient(lifeline_fd, path);
    EXPECT_TRUE(maybe_client_id.has_value());

    const auto& client_id = maybe_client_id.value();
    EXPECT_EQ(client_id.size(), 32);  // hex representation of a 128-bit token.
    EXPECT_TRUE(base::Contains(usb_driver_tracker_.dev_fds_, client_id));
    EXPECT_EQ(usb_driver_tracker_.dev_fds_[client_id].path, path);

    for (auto iface : ifaces) {
      usb_driver_tracker_.dev_fds_[client_id].interfaces.push_back(iface);
      usb_driver_tracker_.dev_ifaces_[path][iface] = client_id;
    }

    return client_id;
  }

 protected:
  testing::NiceMock<MockUsbDriverTracker> usb_driver_tracker_;
  base::ScopedFD pipe_fds_[kMaxNumClients][2];
  base::FilePath temp_file_path_;

 private:
  base::test::TaskEnvironment task_environment_ = base::test::TaskEnvironment(
      base::test::TaskEnvironment::MainThreadType::IO);
};

class UsbDriverTrackerDeathTest : public UsbDriverTrackerTest {
 public:
  void SetUp() override {
    testing::FLAGS_gtest_death_test_style = "threadsafe";
    UsbDriverTrackerTest::SetUp();
  }
};

TEST_F(UsbDriverTrackerTest, RegisterClientSuccess) {
  std::vector<uint8_t> client_0_ifaces = {};
  const auto& path = temp_file_path_;
  SetupClient(kClient0, path, client_0_ifaces);
}

TEST_F(UsbDriverTrackerTest, RegisterClientOpenPathFail) {
  auto path = base::FilePath("notexist");
  auto maybe_client_id =
      usb_driver_tracker_.RegisterClient(pipe_fds_[kClient0][0].get(), path);
  ASSERT_FALSE(maybe_client_id.has_value());
  ASSERT_EQ(0, usb_driver_tracker_.dev_fds_.size());
}

TEST_F(UsbDriverTrackerTest, RegisterClientDupLifelineFdFail) {
  const auto& path = temp_file_path_;
  auto maybe_client_id = usb_driver_tracker_.RegisterClient(-1, path);
  ASSERT_FALSE(maybe_client_id.has_value());
  ASSERT_EQ(0, usb_driver_tracker_.dev_fds_.size());
}

TEST_F(UsbDriverTrackerTest, RegisterClientWatchLifelineFdFail) {
  const auto& path = temp_file_path_;
  EXPECT_CALL(usb_driver_tracker_, WatchLifelineFd)
      .WillOnce(Return(testing::ByMove(nullptr)));
  auto maybe_client_id =
      usb_driver_tracker_.RegisterClient(pipe_fds_[kClient0][0].get(), path);
  ASSERT_FALSE(maybe_client_id.has_value());
  ASSERT_EQ(0, usb_driver_tracker_.dev_fds_.size());
}

TEST_F(UsbDriverTrackerTest, RegisterClientDifferentIds) {
  std::vector<uint8_t> client_0_ifaces = {};
  std::vector<uint8_t> client_1_ifaces = {};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  auto client_1_id = SetupClient(kClient1, path, client_1_ifaces);
  ASSERT_NE(client_0_id, client_1_id);
}

TEST_F(UsbDriverTrackerTest, CleanUpTracking) {
  std::vector<uint8_t> client_0_ifaces = {kIface0};
  std::vector<uint8_t> client_1_ifaces = {kIface1};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  auto client_1_id = SetupClient(kClient1, path, client_1_ifaces);
  EXPECT_CALL(usb_driver_tracker_,
              ConnectInterface(
                  usb_driver_tracker_.dev_fds_[client_0_id].fd.get(), kIface0))
      .WillOnce(Return(true));
  EXPECT_CALL(usb_driver_tracker_,
              ConnectInterface(
                  usb_driver_tracker_.dev_fds_[client_1_id].fd.get(), kIface1))
      .WillOnce(Return(true));
  usb_driver_tracker_.CleanUpTracking();
  ASSERT_EQ(usb_driver_tracker_.dev_fds_.size(), 0);
  ASSERT_FALSE(base::Contains(usb_driver_tracker_.dev_ifaces_, path));
}

TEST_F(UsbDriverTrackerTest, CleanUpTrackingConnectInterfaceFail) {
  std::vector<uint8_t> client_0_ifaces = {kIface0};
  std::vector<uint8_t> client_1_ifaces = {kIface1};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  auto client_1_id = SetupClient(kClient1, path, client_1_ifaces);
  EXPECT_CALL(usb_driver_tracker_,
              ConnectInterface(
                  usb_driver_tracker_.dev_fds_[client_0_id].fd.get(), kIface0))
      .WillOnce(Return(false));
  EXPECT_CALL(usb_driver_tracker_,
              ConnectInterface(
                  usb_driver_tracker_.dev_fds_[client_1_id].fd.get(), kIface1))
      .WillOnce(Return(false));
  usb_driver_tracker_.CleanUpTracking();
  // Even reattach IOCTL fails, the client's tracking should be cleared.
  ASSERT_EQ(usb_driver_tracker_.dev_fds_.size(), 0);
  ASSERT_FALSE(base::Contains(usb_driver_tracker_.dev_ifaces_, path));
}

TEST_F(UsbDriverTrackerTest, HandleClosedFd) {
  base::RunLoop run_loop;
  std::vector<uint8_t> client_0_ifaces = {kIface0, kIface1, kIface2};
  std::string client_0_id;
  const auto& path = temp_file_path_;

  {
    base::ScopedFD pipe_fds[2];
    ASSERT_TRUE(base::CreatePipe(/*read_fd*/ &pipe_fds[0],
                                 /*write_fd*/ &pipe_fds[1],
                                 /*non_blocking*/ true));
    client_0_id =
        SetupClientWithLifelineFd(pipe_fds[0].get(), path, client_0_ifaces);
    for (auto iface : client_0_ifaces) {
      EXPECT_CALL(
          usb_driver_tracker_,
          ConnectInterface(usb_driver_tracker_.dev_fds_[client_0_id].fd.get(),
                           iface))
          .WillOnce(DoAll(QuitRunLoop(&run_loop), Return(true)));
    }
  }
  run_loop.Run();
  ASSERT_FALSE(usb_driver_tracker_.IsClientIdTracked(client_0_id));
  ASSERT_FALSE(base::Contains(usb_driver_tracker_.dev_ifaces_, path));
}

TEST_F(UsbDriverTrackerTest, HandleClosedFdConnectInterfaceError) {
  base::RunLoop run_loop;
  std::vector<uint8_t> client_0_ifaces = {kIface0};
  std::string client_0_id;
  const auto& path = temp_file_path_;

  {
    base::ScopedFD pipe_fds[2];
    ASSERT_TRUE(base::CreatePipe(/*read_fd*/ &pipe_fds[0],
                                 /*write_fd*/ &pipe_fds[1],
                                 /*non_blocking*/ true));
    client_0_id =
        SetupClientWithLifelineFd(pipe_fds[0].get(), path, client_0_ifaces);
    EXPECT_CALL(
        usb_driver_tracker_,
        ConnectInterface(usb_driver_tracker_.dev_fds_[client_0_id].fd.get(),
                         kIface0))
        .WillOnce(DoAll(QuitRunLoop(&run_loop), Return(false)));
  }
  // After client closes, even reattach IOCTL fails, the client's tracking
  // should be cleared.
  run_loop.Run();
  ASSERT_FALSE(usb_driver_tracker_.IsClientIdTracked(client_0_id));
  ASSERT_FALSE(base::Contains(usb_driver_tracker_.dev_ifaces_, path));
}

TEST_F(UsbDriverTrackerTest, HandleClosedFdUnTrackedClientId) {
  std::string untracked_client_id = "abc";
  usb_driver_tracker_.HandleClosedFd(untracked_client_id);
  ASSERT_EQ(usb_driver_tracker_.dev_fds_.size(), 0);
  ASSERT_EQ(usb_driver_tracker_.dev_ifaces_.size(), 0);
}

TEST_F(UsbDriverTrackerTest, HandleClosedFdTwoClientsOnDifferentPaths) {
  base::RunLoop run_loop[kMaxNumClients];
  std::vector<uint8_t> client_ifaces[kMaxNumClients] = {
      {kIface0, kIface1},  // kClient0 ifaces
      {kIface1, kIface0},  // kClient1 ifaces
  };
  std::string client_id[kMaxNumClients];

  base::FilePath another_file_path;
  ASSERT_TRUE(CreateTemporaryFile(&another_file_path));

  base::FilePath paths[kMaxNumClients] = {
      temp_file_path_,    // kClient0 path
      another_file_path,  // kClient1 path
  };
  ASSERT_NE(paths[kClient0], paths[kClient1]);

  {
    base::ScopedFD pipe_fds[kMaxNumClients][2];
    for (auto client = 0; client < kMaxNumClients; client++) {
      ASSERT_TRUE(base::CreatePipe(/*read_fd*/ &pipe_fds[client][0],
                                   /*write_fd*/ &pipe_fds[client][1],
                                   /*non_blocking*/ true));
      client_id[client] = SetupClientWithLifelineFd(
          pipe_fds[client][0].get(), paths[client], client_ifaces[client]);
      for (auto iface : client_ifaces[client]) {
        EXPECT_CALL(
            usb_driver_tracker_,
            ConnectInterface(
                usb_driver_tracker_.dev_fds_[client_id[client]].fd.get(),
                iface))
            .WillOnce(DoAll(QuitRunLoop(&run_loop[client]), Return(true)));
      }
    }
  }
  for (auto client = 0; client < kMaxNumClients; client++) {
    run_loop[client].Run();
    ASSERT_FALSE(usb_driver_tracker_.IsClientIdTracked(client_id[client]));
    ASSERT_FALSE(
        base::Contains(usb_driver_tracker_.dev_ifaces_, paths[client]));
  }
  ASSERT_EQ(0, usb_driver_tracker_.dev_fds_.size());
  ASSERT_EQ(0, usb_driver_tracker_.dev_ifaces_.size());
}

TEST_F(UsbDriverTrackerTest, HandleClosedFdTwoClientsOnSamePath) {
  base::RunLoop run_loop[kMaxNumClients];
  std::vector<uint8_t> client_ifaces[kMaxNumClients] = {
      {kIface0, kIface1},  // kClient0 ifaces
      {kIface2},           // kClient1 ifaces
  };
  std::string client_id[kMaxNumClients];
  const auto& path = temp_file_path_;

  {
    base::ScopedFD pipe_fds[kMaxNumClients][2];
    for (auto client = 0; client < kMaxNumClients; client++) {
      ASSERT_TRUE(base::CreatePipe(/*read_fd*/ &pipe_fds[client][0],
                                   /*write_fd*/ &pipe_fds[client][1],
                                   /*non_blocking*/ true));
      client_id[client] = SetupClientWithLifelineFd(
          pipe_fds[client][0].get(), path, client_ifaces[client]);
      for (auto iface : client_ifaces[client]) {
        EXPECT_CALL(
            usb_driver_tracker_,
            ConnectInterface(
                usb_driver_tracker_.dev_fds_[client_id[client]].fd.get(),
                iface))
            .WillOnce(DoAll(QuitRunLoop(&run_loop[client]), Return(true)));
      }
    }
  }
  for (auto client = 0; client < kMaxNumClients; client++) {
    run_loop[client].Run();
    ASSERT_FALSE(usb_driver_tracker_.IsClientIdTracked(client_id[client]));
  }
  ASSERT_FALSE(base::Contains(usb_driver_tracker_.dev_ifaces_, path));
  ASSERT_EQ(0, usb_driver_tracker_.dev_fds_.size());
  ASSERT_EQ(0, usb_driver_tracker_.dev_ifaces_.size());
}
TEST_F(UsbDriverTrackerTest, RecordInterfaceDetached) {
  std::vector<uint8_t> client_0_ifaces = {};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  ASSERT_FALSE(base::Contains(usb_driver_tracker_.dev_ifaces_, path));
  usb_driver_tracker_.RecordInterfaceDetached(client_0_id, path, kIface0);
  ASSERT_EQ(usb_driver_tracker_.dev_ifaces_[path][kIface0], client_0_id);
}

TEST_F(UsbDriverTrackerTest, ClearDetachedInterfaceRecord) {
  std::vector<uint8_t> client_0_ifaces = {kIface0};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  ASSERT_TRUE(usb_driver_tracker_.dev_ifaces_[path][kIface0] == client_0_id);
  usb_driver_tracker_.ClearDetachedInterfaceRecord(client_0_id, path, kIface0);
  ASSERT_FALSE(base::Contains(usb_driver_tracker_.dev_ifaces_, path));
}

TEST_F(UsbDriverTrackerDeathTest, RecordInterfaceDetachedUntrackedClient) {
  std::string untracked_client_id = "abc";
  const auto& path = temp_file_path_;
  ASSERT_DEBUG_DEATH(usb_driver_tracker_.RecordInterfaceDetached(
                         untracked_client_id, path, kIface0),
                     "");
}

TEST_F(UsbDriverTrackerDeathTest, RecordInterfaceDetachedIfaceWatched) {
  std::vector<uint8_t> client_0_ifaces = {kIface0};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  ASSERT_DEBUG_DEATH(
      usb_driver_tracker_.RecordInterfaceDetached(client_0_id, path, kIface0),
      "");
}

TEST_F(UsbDriverTrackerDeathTest, ClearDetachedInterfaceRecordUntrackedClient) {
  std::string untracked_client_id = "abc";
  const auto& path = temp_file_path_;
  ASSERT_DEBUG_DEATH(usb_driver_tracker_.ClearDetachedInterfaceRecord(
                         untracked_client_id, path, kIface0),
                     "");
}

TEST_F(UsbDriverTrackerDeathTest, ClearDetachedInterfaceRecordUnknownPath) {
  std::vector<uint8_t> client_0_ifaces = {kIface0};
  const auto& path = temp_file_path_;
  base::FilePath unknown_file_path("unknown_path");
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  ASSERT_DEBUG_DEATH(usb_driver_tracker_.ClearDetachedInterfaceRecord(
                         client_0_id, unknown_file_path, kIface0),
                     "");
}

TEST_F(UsbDriverTrackerDeathTest, ClearDetachedInterfaceRecordDupIface) {
  std::vector<uint8_t> client_0_ifaces = {kIface0, kIface0};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  ASSERT_DEBUG_DEATH(usb_driver_tracker_.ClearDetachedInterfaceRecord(
                         client_0_id, path, kIface0),
                     "");
  // Explicitly clear the tracking structure to avoid DCHECK failure in
  // destructor.
  usb_driver_tracker_.dev_fds_.clear();
}

TEST_F(UsbDriverTrackerTest, DetachInterfaceSuccess) {
  std::vector<uint8_t> client_0_ifaces = {};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  EXPECT_CALL(usb_driver_tracker_,
              DisconnectInterface(
                  usb_driver_tracker_.dev_fds_[client_0_id].fd.get(), kIface0))
      .WillOnce(Return(true));
  ASSERT_TRUE(usb_driver_tracker_.DetachInterface(client_0_id, kIface0));
  ASSERT_EQ(usb_driver_tracker_.dev_fds_[client_0_id].interfaces[0], kIface0);
  ASSERT_EQ(usb_driver_tracker_.dev_ifaces_[path][kIface0], client_0_id);
}

TEST_F(UsbDriverTrackerTest, DetachInterfaceUnTrackedClientFail) {
  std::string untracked_client_id = "abc";
  ASSERT_FALSE(
      usb_driver_tracker_.DetachInterface(untracked_client_id, kIface0));
  ASSERT_EQ(usb_driver_tracker_.dev_fds_.size(), 0);
  ASSERT_EQ(usb_driver_tracker_.dev_ifaces_.size(), 0);
}

TEST_F(UsbDriverTrackerTest, DetachInterfaceIfaceAlreadyDetachedByOtherClient) {
  std::vector<uint8_t> client_0_ifaces = {};
  std::vector<uint8_t> client_1_ifaces = {kIface0};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  SetupClient(kClient1, path, client_1_ifaces);
  ASSERT_FALSE(usb_driver_tracker_.DetachInterface(client_0_id, kIface0));
}

TEST_F(UsbDriverTrackerTest,
       DetachInterfaceIfaceAlreadyDetachedByTheClientNoOp) {
  std::vector<uint8_t> client_0_ifaces = {kIface0};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  ASSERT_TRUE(usb_driver_tracker_.DetachInterface(client_0_id, kIface0));
}

TEST_F(UsbDriverTrackerTest, DetachInterfaceIfaceDisconnectFail) {
  std::vector<uint8_t> client_0_ifaces = {};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  EXPECT_CALL(usb_driver_tracker_,
              DisconnectInterface(
                  usb_driver_tracker_.dev_fds_[client_0_id].fd.get(), kIface0))
      .WillOnce(Return(false));
  ASSERT_FALSE(usb_driver_tracker_.DetachInterface(client_0_id, kIface0));
  ASSERT_EQ(usb_driver_tracker_.dev_ifaces_.size(), 0);
}

TEST_F(UsbDriverTrackerTest, ReattachInterfaceSuccess) {
  std::vector<uint8_t> client_0_ifaces = {kIface0};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  EXPECT_CALL(usb_driver_tracker_,
              ConnectInterface(
                  usb_driver_tracker_.dev_fds_[client_0_id].fd.get(), kIface0))
      .WillOnce(Return(true));
  ASSERT_TRUE(usb_driver_tracker_.ReattachInterface(client_0_id, kIface0));
  ASSERT_EQ(usb_driver_tracker_.dev_ifaces_.size(), 0);
  // The client id should still be tracked even it doesn't have any ifaces
  // detached.
  ASSERT_TRUE(usb_driver_tracker_.IsClientIdTracked(client_0_id));
}

TEST_F(UsbDriverTrackerTest, ReattachInterfaceUntrackedClientFail) {
  std::string untracked_client_id = "abc";
  ASSERT_FALSE(
      usb_driver_tracker_.ReattachInterface(untracked_client_id, kIface0));
}

TEST_F(UsbDriverTrackerTest, ReattachInterfacePathNoIfaceDetachedNoOp) {
  std::vector<uint8_t> client_0_ifaces = {};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  ASSERT_TRUE(usb_driver_tracker_.ReattachInterface(client_0_id, kIface0));
  ASSERT_EQ(usb_driver_tracker_.dev_ifaces_.size(), 0);
}

TEST_F(UsbDriverTrackerTest, ReattachInterfaceIfaceNotDetachedNoOp) {
  std::vector<uint8_t> client_0_ifaces = {kIface1};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  ASSERT_TRUE(usb_driver_tracker_.ReattachInterface(client_0_id, kIface0));
  ASSERT_EQ(usb_driver_tracker_.dev_ifaces_[path][kIface1], client_0_id);
}

TEST_F(UsbDriverTrackerTest, ReattachInterfaceIfaceDetachedByOtherClient) {
  std::vector<uint8_t> client_0_ifaces = {};
  std::vector<uint8_t> client_1_ifaces = {kIface0};
  const auto& path = temp_file_path_;
  auto client_0_id = SetupClient(kClient0, path, client_0_ifaces);
  SetupClient(kClient1, path, client_1_ifaces);
  ASSERT_FALSE(usb_driver_tracker_.ReattachInterface(client_0_id, kIface0));
}

}  // namespace permission_broker
