// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_manager.h"

#include <sys/epoll.h>

#include <vector>

#include <base/task/single_thread_task_executor.h>
#include <gtest/gtest.h>

namespace brillo {

class UsbManagerTest : public testing::Test {
 protected:
  class TestUsbManager : public UsbManager {
   public:
    using UsbManager::StartWatchingFileDescriptor;
    using UsbManager::StopWatchingAllFileDescriptors;
    using UsbManager::StopWatchingFileDescriptor;
  };

  void TearDown() override {
    // Close all file descriptors opened by CreatePollFileDescriptor().
    for (int file_descriptor : file_descriptors_) {
      close(file_descriptor);
    }
    file_descriptors_.clear();
  }

  // Creates and returns an epoll file descriptor that can be watched by
  // UsbManager::StartWatchingFileDescriptor().
  int CreatePollFileDescriptor() {
    int file_descriptor = epoll_create1(0);
    EXPECT_NE(-1, file_descriptor);
    file_descriptors_.push_back(file_descriptor);
    return file_descriptor;
  }

  base::SingleThreadTaskExecutor task_executor_{base::MessagePumpType::IO};
  base::FileDescriptorWatcher watcher_{task_executor_.task_runner()};
  TestUsbManager usb_manager_;
  std::vector<int> file_descriptors_;
};

TEST_F(UsbManagerTest, StartAndStopWatchingFileDescriptor) {
  int file_descriptor = CreatePollFileDescriptor();

  // StopWatchingFileDescriptor on a file descriptor, which is not being
  // watched, should fail.
  EXPECT_FALSE(usb_manager_.StopWatchingFileDescriptor(file_descriptor));

  EXPECT_TRUE(usb_manager_.StartWatchingFileDescriptor(
      file_descriptor, brillo::Stream::AccessMode::READ, base::DoNothing()));

  // StartWatchingFileDescriptor on the same file descriptor should be ok.
  EXPECT_TRUE(usb_manager_.StartWatchingFileDescriptor(
      file_descriptor, brillo::Stream::AccessMode::READ, base::DoNothing()));
  EXPECT_TRUE(usb_manager_.StartWatchingFileDescriptor(
      file_descriptor, brillo::Stream::AccessMode::WRITE, base::DoNothing()));
  EXPECT_TRUE(usb_manager_.StartWatchingFileDescriptor(
      file_descriptor, brillo::Stream::AccessMode::READ_WRITE,
      base::DoNothing()));
  EXPECT_TRUE(usb_manager_.StopWatchingFileDescriptor(file_descriptor));
  EXPECT_FALSE(usb_manager_.StopWatchingFileDescriptor(file_descriptor));
}

TEST_F(UsbManagerTest, StopWatchingAllFileDescriptors) {
  int file_descriptor1 = CreatePollFileDescriptor();
  int file_descriptor2 = CreatePollFileDescriptor();

  EXPECT_TRUE(usb_manager_.StartWatchingFileDescriptor(
      file_descriptor1, brillo::Stream::AccessMode::READ, base::DoNothing()));
  EXPECT_TRUE(usb_manager_.StartWatchingFileDescriptor(
      file_descriptor2, brillo::Stream::AccessMode::READ, base::DoNothing()));
  usb_manager_.StopWatchingAllFileDescriptors();
  EXPECT_FALSE(usb_manager_.StopWatchingFileDescriptor(file_descriptor1));
  EXPECT_FALSE(usb_manager_.StopWatchingFileDescriptor(file_descriptor2));
}

}  // namespace brillo
