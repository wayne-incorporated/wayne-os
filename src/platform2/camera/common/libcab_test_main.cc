// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <semaphore.h>
#include <sys/mman.h>

#include <list>
#include <unordered_map>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/writable_shared_memory_region.h>
#include <brillo/message_loops/base_message_loop.h>
#include <gtest/gtest.h>

#include "common/libcab_test_internal.h"
#include "cros-camera/camera_algorithm_bridge.h"
#include "cros-camera/common.h"

namespace libcab_test {

class CameraAlgorithmBridgeFixture : public testing::Test,
                                     public camera_algorithm_callback_ops_t {
 public:
  const size_t kShmBufferSize = 2048;

  CameraAlgorithmBridgeFixture()
      : mojo_manager_token_(
            cros::CameraMojoChannelManagerToken::CreateInstance()) {
    CameraAlgorithmBridgeFixture::return_callback =
        CameraAlgorithmBridgeFixture::ReturnCallbackForwarder;
    CameraAlgorithmBridgeFixture::update =
        CameraAlgorithmBridgeFixture::UpdateForwarder;
    bridge_ = cros::CameraAlgorithmBridge::CreateInstance(
        cros::CameraAlgorithmBackend::kTest, mojo_manager_token_.get());
    if (!bridge_ || bridge_->Initialize(this) != 0) {
      ADD_FAILURE() << "Failed to initialize camera algorithm bridge";
      return;
    }
    sem_init(&return_sem_, 0, 0);
    sem_init(&update_sem_, 0, 0);
  }

  CameraAlgorithmBridgeFixture(const CameraAlgorithmBridgeFixture&) = delete;
  CameraAlgorithmBridgeFixture& operator=(const CameraAlgorithmBridgeFixture&) =
      delete;

  ~CameraAlgorithmBridgeFixture() override {
    sem_destroy(&return_sem_);
    sem_destroy(&update_sem_);
  }

  void Request(const std::vector<uint8_t>& req_header, int32_t buffer_handle) {
    {
      base::AutoLock l(request_map_lock_);
      request_map_[req_id_] = buffer_handle;
    }
    bridge_->Request(req_id_++, req_header, buffer_handle);
  }

  cros::CameraMojoChannelManagerToken* GetMojoManagerTokenInstance() {
    return mojo_manager_token_.get();
  }

 protected:
  static void ReturnCallbackForwarder(
      const camera_algorithm_callback_ops_t* callback_ops,
      uint32_t req_id,
      uint32_t status,
      int32_t buffer_handle) {
    if (callback_ops) {
      auto s = const_cast<CameraAlgorithmBridgeFixture*>(
          static_cast<const CameraAlgorithmBridgeFixture*>(callback_ops));
      s->ReturnCallback(req_id, status, buffer_handle);
    }
  }

  virtual void ReturnCallback(uint32_t req_id,
                              uint32_t status,
                              int32_t buffer_handle) {
    base::AutoLock l(request_map_lock_);
    if (request_map_.find(req_id) == request_map_.end() ||
        request_map_[req_id] != buffer_handle) {
      ADD_FAILURE()
          << "Invalid request id or handle received from the return callback";
      return;
    }
    status_list_.push_back(status);
    request_map_.erase(req_id);
    sem_post(&return_sem_);
  }

  static void UpdateForwarder(
      const camera_algorithm_callback_ops_t* callback_ops,
      uint32_t upd_id,
      const uint8_t upd_header[],
      uint32_t size,
      int buffer_fd) {
    if (callback_ops) {
      auto s = const_cast<CameraAlgorithmBridgeFixture*>(
          static_cast<const CameraAlgorithmBridgeFixture*>(callback_ops));
      s->Update(upd_id, upd_header, size, buffer_fd);
    }
  }

  virtual void Update(uint32_t upd_id,
                      const uint8_t upd_header[],
                      uint32_t size,
                      int buffer_fd) {
    struct stat sb;
    if (fstat(buffer_fd, &sb) == -1) {
      ADD_FAILURE() << "Failed to get buffer status";
      return;
    }
    uint8_t* read_ptr = static_cast<uint8_t*>(
        mmap(nullptr, sb.st_size, PROT_WRITE, MAP_SHARED, buffer_fd, 0));
    if (read_ptr == nullptr) {
      ADD_FAILURE() << "Failed to map buffer";
      return;
    }
    uint32_t hashcode;
    hashcode =
        *static_cast<const uint32_t*>(static_cast<const void*>(upd_header));
    if (hashcode != SimpleHash(read_ptr, sb.st_size)) {
      ADD_FAILURE() << "Shared memory content is corrupted";
      return;
    }
    upd_id_ = upd_id;
    buffer_fd_ = buffer_fd;
    sem_post(&update_sem_);
  }

  // |mojo_manager_| should only be destroyed after any usage of it. So it
  // should be declared first.
  std::unique_ptr<cros::CameraMojoChannelManagerToken> mojo_manager_token_;

  std::unique_ptr<cros::CameraAlgorithmBridge> bridge_;

  std::list<int32_t> status_list_;

  sem_t return_sem_;

  uint32_t upd_id_;

  int buffer_fd_;

  sem_t update_sem_;

 private:
  uint32_t req_id_ = 0;

  base::Lock request_map_lock_;

  std::unordered_map<uint32_t, int32_t> request_map_;
};

TEST_F(CameraAlgorithmBridgeFixture, BasicOperation) {
  base::WritableSharedMemoryRegion shm_region =
      base::WritableSharedMemoryRegion::Create(kShmBufferSize);
  ASSERT_TRUE(shm_region.IsValid()) << "Failed to create shared memory region";
  base::WritableSharedMemoryMapping shm_mapping = shm_region.Map();
  ASSERT_TRUE(shm_mapping.IsValid())
      << "Failed to create shared memory mapping";
  base::subtle::PlatformSharedMemoryRegion platform_shm =
      base::WritableSharedMemoryRegion::TakeHandleForSerialization(
          std::move(shm_region));
  int32_t handle = bridge_->RegisterBuffer(platform_shm.GetPlatformHandle().fd);
  ASSERT_LE(0, handle) << "Handle should be of positive value";
  std::vector<uint8_t> req_header(1, REQUEST_TEST_COMMAND_NORMAL);
  Request(req_header, handle);
  struct timespec timeout = {};
  clock_gettime(CLOCK_REALTIME, &timeout);
  timeout.tv_sec += 1;
  ASSERT_EQ(0, sem_timedwait(&return_sem_, &timeout));
  ASSERT_EQ(0, status_list_.front());
  std::vector<int32_t> handles({handle});
  bridge_->DeregisterBuffers(handles);
}

TEST_F(CameraAlgorithmBridgeFixture, InvalidFdOrHandle) {
  int32_t handle = bridge_->RegisterBuffer(-1);
  ASSERT_GT(0, handle) << "Registering invalid fd should have failed";

  base::WritableSharedMemoryRegion shm_region =
      base::WritableSharedMemoryRegion::Create(kShmBufferSize);
  ASSERT_TRUE(shm_region.IsValid()) << "Failed to create shared memory region";
  base::WritableSharedMemoryMapping shm_mapping = shm_region.Map();
  ASSERT_TRUE(shm_mapping.IsValid())
      << "Failed to create shared memory mapping";
  base::subtle::PlatformSharedMemoryRegion platform_shm =
      base::WritableSharedMemoryRegion::TakeHandleForSerialization(
          std::move(shm_region));
  handle = bridge_->RegisterBuffer(platform_shm.GetPlatformHandle().fd);
  ASSERT_LE(0, handle) << "Handle should be of positive value";
  std::vector<uint8_t> req_header(1, REQUEST_TEST_COMMAND_NORMAL);
  Request(req_header, handle - 1);
  Request(req_header, handle + 1);
  struct timespec timeout = {};
  clock_gettime(CLOCK_REALTIME, &timeout);
  timeout.tv_sec += 1;
  for (uint32_t i = 0; i < 2; i++) {
    ASSERT_EQ(0, sem_timedwait(&return_sem_, &timeout));
  }
  for (const auto& it : status_list_) {
    ASSERT_EQ(-EBADF, it);
  }
  std::vector<int32_t> handles({handle});
  bridge_->DeregisterBuffers(handles);

  // Closes the fd to fail RegisterBuffer.
  // PassPlatformHandle() passes ownership to the returned |ScopedFDPair|, while
  // get() does not transfer the ownership.
  // When the temporary variable is destructed at the end of the statement, the
  // fd is closed.
  int fd = platform_shm.PassPlatformHandle().fd.get();
  ASSERT_GT(0, bridge_->RegisterBuffer(fd))
      << "Registering invalid fd should have failed";
}

TEST_F(CameraAlgorithmBridgeFixture, MultiRequests) {
  const size_t kNumberOfFds = 256;

  std::vector<base::subtle::PlatformSharedMemoryRegion> platform_shms(
      kNumberOfFds);
  std::vector<int> handles(kNumberOfFds);
  for (uint32_t i = 0; i < kNumberOfFds; i++) {
    base::WritableSharedMemoryRegion shm_region =
        base::WritableSharedMemoryRegion::Create(kShmBufferSize);
    ASSERT_TRUE(shm_region.IsValid())
        << "Failed to create shared memory region";
    platform_shms[i] =
        base::WritableSharedMemoryRegion::TakeHandleForSerialization(
            std::move(shm_region));
    handles[i] =
        bridge_->RegisterBuffer(platform_shms[i].GetPlatformHandle().fd);
    ASSERT_LE(0, handles[i]) << "Handle should be of positive value";
  }
  for (const auto handle : handles) {
    std::vector<uint8_t> req_header(1, REQUEST_TEST_COMMAND_NORMAL);
    Request(req_header, handle);
  }
  struct timespec timeout = {};
  clock_gettime(CLOCK_REALTIME, &timeout);
  timeout.tv_sec += 1;
  for (size_t i = 0; i < handles.size(); ++i) {
    ASSERT_EQ(0, sem_timedwait(&return_sem_, &timeout));
  }
  for (const auto& it : status_list_) {
    ASSERT_EQ(0, it);
  }
  bridge_->DeregisterBuffers(handles);
}

TEST_F(CameraAlgorithmBridgeFixture, DeadLockRecovery) {
  // Create a dead lock in the algorithm.
  std::vector<uint8_t> req_header(1, REQUEST_TEST_COMMAND_DEAD_LOCK);
  Request(req_header, -1);
  struct timespec timeout = {};
  clock_gettime(CLOCK_REALTIME, &timeout);
  timeout.tv_sec += 1;
  ASSERT_NE(0, sem_timedwait(&return_sem_, &timeout));
  // Reconnect the bridge.
  bridge_ = cros::CameraAlgorithmBridge::CreateInstance(
      cros::CameraAlgorithmBackend::kTest, GetMojoManagerTokenInstance());
  ASSERT_NE(nullptr, bridge_);
  ASSERT_EQ(0, bridge_->Initialize(this));
  base::WritableSharedMemoryRegion shm_region =
      base::WritableSharedMemoryRegion::Create(kShmBufferSize);
  ASSERT_TRUE(shm_region.IsValid()) << "Failed to create shared memory region";
  base::WritableSharedMemoryMapping shm_mapping = shm_region.Map();
  ASSERT_TRUE(shm_mapping.IsValid())
      << "Failed to create shared memory mapping";
  base::subtle::PlatformSharedMemoryRegion platform_shm =
      base::WritableSharedMemoryRegion::TakeHandleForSerialization(
          std::move(shm_region));
  int32_t handle = bridge_->RegisterBuffer(platform_shm.GetPlatformHandle().fd);
  ASSERT_LE(0, handle) << "Handle should be of positive value";
  req_header = std::vector<uint8_t>(1, REQUEST_TEST_COMMAND_NORMAL);
  Request(req_header, handle);
  clock_gettime(CLOCK_REALTIME, &timeout);
  timeout.tv_sec += 1;
  ASSERT_EQ(0, sem_timedwait(&return_sem_, &timeout));
  ASSERT_EQ(0, status_list_.front());
  std::vector<int32_t> handles({handle});
  bridge_->DeregisterBuffers(handles);
}

TEST_F(CameraAlgorithmBridgeFixture, VerifyUpdate) {
  std::vector<uint8_t> req_header(1, REQUEST_TEST_COMMAND_VERIFY_UPDATE);
  Request(req_header, -1);
  struct timespec timeout = {};
  clock_gettime(CLOCK_REALTIME, &timeout);
  timeout.tv_sec += 1;
  ASSERT_EQ(0, sem_timedwait(&update_sem_, &timeout));
  bridge_->UpdateReturn(upd_id_, 0, buffer_fd_);
  ASSERT_EQ(0, sem_timedwait(&return_sem_, &timeout));
}

class CameraAlgorithmBridgeStatusFixture : public CameraAlgorithmBridgeFixture {
 public:
  CameraAlgorithmBridgeStatusFixture() = default;
  CameraAlgorithmBridgeStatusFixture(
      const CameraAlgorithmBridgeStatusFixture&) = delete;
  CameraAlgorithmBridgeStatusFixture& operator=(
      const CameraAlgorithmBridgeStatusFixture&) = delete;

 protected:
  void ReturnCallback(uint32_t req_id,
                      uint32_t status,
                      int32_t buffer_handle) override {
    base::AutoLock l(hash_codes_lock_);
    if (buffer_handle < 0 ||
        static_cast<size_t>(buffer_handle) >= hash_codes_.size() ||
        hash_codes_[buffer_handle] != status) {
      ADD_FAILURE() << "Invalid status received from the return callback";
      return;
    }
    sem_post(&return_sem_);
  }

  base::Lock hash_codes_lock_;

  // Stores hashcode generated from |req_header| of the Request calls.
  std::vector<uint32_t> hash_codes_;
};

static int GenerateRandomHeader(uint32_t max_header_len,
                                std::vector<uint8_t>* header) {
  if (max_header_len == 0 || !header) {
    return -EINVAL;
  }
  static unsigned int seed = time(NULL) + getpid();
  header->resize((rand_r(&seed) % max_header_len) + 1);
  for (auto& it : *header) {
    it = rand_r(&seed);
  }
  return 0;
}

TEST_F(CameraAlgorithmBridgeStatusFixture, VerifyReturnStatus) {
  const uint32_t kNumberOfTests = 256;
  const uint32_t kMaxReqHeaderSize = 64;
  for (uint32_t i = 0; i <= kNumberOfTests; i++) {
    std::vector<uint8_t> req_header;
    GenerateRandomHeader(kMaxReqHeaderSize, &req_header);
    req_header[0] = REQUEST_TEST_COMMAND_VERIFY_STATUS;
    {
      base::AutoLock l(hash_codes_lock_);
      hash_codes_.push_back(SimpleHash(req_header.data(), req_header.size()));
    }
    Request(req_header, i);
  }
  struct timespec timeout = {};
  clock_gettime(CLOCK_REALTIME, &timeout);
  timeout.tv_sec += 1;
  for (uint32_t i = 0; i <= kNumberOfTests; i++) {
    ASSERT_EQ(0, sem_timedwait(&return_sem_, &timeout));
  }
}

}  // namespace libcab_test

int main(int argc, char** argv) {
  static base::AtExitManager exit_manager;

  // Set up logging so we can enable VLOGs with -v / --vmodule.
  base::CommandLine::Init(argc, argv);
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  LOG_ASSERT(logging::InitLogging(settings));

  brillo::BaseMessageLoop message_loop;
  message_loop.SetAsCurrent();

  // Initialize and run all tests
  ::testing::InitGoogleTest(&argc, argv);
  int result = RUN_ALL_TESTS();

  return result;
}
