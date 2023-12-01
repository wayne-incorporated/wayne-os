// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/mojo_proxy/proxy_file_system.h"

#include <unistd.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/posix/eintr_wrapper.h>
#include <base/synchronization/waitable_event.h>
#include <base/test/task_environment.h>
#include <base/threading/thread.h>
#include <gtest/gtest.h>

namespace arc {
namespace {

constexpr int64_t kHandle = 123;
constexpr char kTestData[] = "abcdefghijklmnopqrstuvwxyz";

class ProxyFileSystemTest : public testing::Test,
                            public ProxyFileSystem::Delegate {
 public:
  ProxyFileSystemTest() = default;
  ~ProxyFileSystemTest() override = default;
  ProxyFileSystemTest(const ProxyFileSystemTest&) = delete;
  ProxyFileSystemTest& operator=(const ProxyFileSystemTest&) = delete;

  void SetUp() override {
    ASSERT_TRUE(mount_dir_.CreateUniqueTempDir());

    ASSERT_TRUE(delegate_thread_.Start());

    ASSERT_TRUE(file_system_thread_.StartWithOptions(
        base::Thread::Options(base::MessagePumpType::IO, 0)));

    file_system_ = std::make_unique<ProxyFileSystem>(
        this, delegate_thread_.task_runner(), mount_dir_.GetPath());
    bool result = false;
    file_system_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce([](ProxyFileSystem* file_system,
                          bool* result) { *result = file_system->Init(); },
                       file_system_.get(), &result));
    file_system_thread_.FlushForTesting();
    ASSERT_TRUE(result);
  }

  // ProxyFileSystem::Delegate overridess:
  void Pread(int64_t handle,
             uint64_t count,
             uint64_t offset,
             PreadCallback callback) override {
    if (handle == kHandle) {
      offset = std::min(static_cast<uint64_t>(data_.size()), offset);
      count = std::min(static_cast<uint64_t>(data_.size()) - offset, count);
      std::move(callback).Run(0, data_.substr(offset, count));
    } else {
      std::move(callback).Run(EBADF, std::string());
    }
  }
  void Pwrite(int64_t handle,
              std::string blob,
              uint64_t offset,
              PwriteCallback callback) override {
    if (handle == kHandle) {
      data_.resize(
          std::max(data_.size(), static_cast<size_t>(offset + blob.size())));
      data_.replace(offset, blob.size(), blob);
      std::move(callback).Run(0, blob.size());
    } else {
      std::move(callback).Run(EBADF, 0);
    }
  }
  void Close(int64_t handle) override {
    EXPECT_FALSE(close_was_called_.IsSignaled());
    EXPECT_EQ(kHandle, handle);
    close_was_called_.Signal();
  }
  void Fstat(int64_t handle, FstatCallback callback) override {
    if (handle == kHandle) {
      std::move(callback).Run(0, data_.size());
    } else {
      std::move(callback).Run(EBADF, 0);
    }
  }
  void Ftruncate(int64_t handle,
                 int64_t length,
                 FtruncateCallback callback) override {
    if (handle == kHandle) {
      data_.resize(length);
      std::move(callback).Run(0);
    } else {
      std::move(callback).Run(EBADF);
    }
  }

 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
      base::test::TaskEnvironment::MainThreadType::IO};

  // Mount point for ProxyFileSystem.
  base::ScopedTempDir mount_dir_;

  base::Thread delegate_thread_{"FileSystemDelegate"};
  base::Thread file_system_thread_{"FileSystem"};

  // ProxyFileSystem to be tested.
  std::unique_ptr<ProxyFileSystem> file_system_;

  base::WaitableEvent close_was_called_{
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED};

  std::string data_;
};

// On ARM devices, unit tests run without necessary capabilities in QEMU.
// TODO(b/270608749): Migrate to VM tests.
TEST_F(ProxyFileSystemTest, DISABLED_RegularFileReadTest) {
  data_ = kTestData;

  base::ScopedFD fd = file_system_->RegisterHandle(kHandle, O_RDONLY);
  char buf[10];
  ASSERT_EQ(sizeof(buf), HANDLE_EINTR(read(fd.get(), buf, sizeof(buf))));
  EXPECT_EQ("abcdefghij", std::string(buf, sizeof(buf)));
  ASSERT_EQ(sizeof(buf), HANDLE_EINTR(read(fd.get(), buf, sizeof(buf))));
  EXPECT_EQ("klmnopqrst", std::string(buf, sizeof(buf)));
  ASSERT_EQ(6, HANDLE_EINTR(read(fd.get(), buf, sizeof(buf))));
  EXPECT_EQ("uvwxyz", std::string(buf, 6));
  // Make sure EOF.
  ASSERT_EQ(0, HANDLE_EINTR(read(fd.get(), buf, sizeof(buf))));

  // Close the file descriptor.
  fd.reset();
  close_was_called_.Wait();
}

// On ARM devices, unit tests run without necessary capabilities in QEMU.
// TODO(b/270608749): Migrate to VM tests.
TEST_F(ProxyFileSystemTest, DISABLED_RegularFileWriteTest) {
  base::ScopedFD fd = file_system_->RegisterHandle(kHandle, O_WRONLY);
  ASSERT_EQ(10, HANDLE_EINTR(write(fd.get(), kTestData, 10)));
  ASSERT_EQ(10, HANDLE_EINTR(write(fd.get(), kTestData + 10, 10)));
  ASSERT_EQ(6, HANDLE_EINTR(write(fd.get(), kTestData + 20, 6)));
  EXPECT_EQ(kTestData, data_);

  // Close the file descriptor.
  fd.reset();
  close_was_called_.Wait();
}

// On ARM devices, unit tests run without necessary capabilities in QEMU.
// TODO(b/270608749): Migrate to VM tests.
TEST_F(ProxyFileSystemTest, DISABLED_RegularFileReadWriteTest) {
  base::ScopedFD fd = file_system_->RegisterHandle(kHandle, O_RDWR);
  ASSERT_EQ(26, HANDLE_EINTR(pwrite(fd.get(), kTestData, 26, 0)));
  EXPECT_EQ(kTestData, data_);

  char buf[26];
  ASSERT_EQ(sizeof(buf), HANDLE_EINTR(pread(fd.get(), buf, sizeof(buf), 0)));
  EXPECT_EQ(kTestData, std::string(buf, sizeof(buf)));

  // Close the file descriptor.
  fd.reset();
  close_was_called_.Wait();
}

// On ARM devices, unit tests run without necessary capabilities in QEMU.
// TODO(b/270608749): Migrate to VM tests.
TEST_F(ProxyFileSystemTest, DISABLED_RegularFileTruncateAndStatTest) {
  constexpr int64_t kLength = 5;
  base::ScopedFD fd = file_system_->RegisterHandle(kHandle, O_RDWR);
  EXPECT_EQ(0, HANDLE_EINTR(ftruncate(fd.get(), kLength)));

  struct stat attr = {};
  ASSERT_EQ(0, fstat(fd.get(), &attr));
  EXPECT_EQ(kLength, attr.st_size);

  // Close the file descriptor.
  fd.reset();
  close_was_called_.Wait();
}

}  // namespace
}  // namespace arc
