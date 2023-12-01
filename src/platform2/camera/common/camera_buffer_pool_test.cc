/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "camera/common/camera_buffer_pool.h"

#include <optional>
#include <vector>

#include <gtest/gtest.h>

namespace cros {

// Fake scoped buffer implementations.
ScopedBufferHandle CameraBufferManager::AllocateScopedBuffer(size_t width,
                                                             size_t height,
                                                             uint32_t format,
                                                             uint32_t usage) {
  return ScopedBufferHandle(new buffer_handle_t(new native_handle_t{}));
}

void BufferHandleDeleter::operator()(buffer_handle_t* handle) {
  if (handle) {
    delete *handle;
    delete handle;
  }
}

ScopedMapping::~ScopedMapping() {}

// Tests.
TEST(CameraBufferPoolTest, RequestAndReleaseBuffers) {
  CameraBufferPool::Options options = {
      .width = 320,
      .height = 240,
      .format = HAL_PIXEL_FORMAT_YCbCr_420_888,
      .usage = 0,
      .max_num_buffers = 100,
  };
  CameraBufferPool pool(options);

  // Test requesting and releasing 1-N buffers in batch.
  for (size_t i = 1; i <= options.max_num_buffers; ++i) {
    std::vector<CameraBufferPool::Buffer> buffers;
    for (size_t j = 0; j < i; ++j) {
      std::optional<CameraBufferPool::Buffer> buffer = pool.RequestBuffer();
      ASSERT_TRUE(buffer.has_value());
      ASSERT_NE(buffer->handle(), nullptr);
      buffers.push_back(*std::move(buffer));
    }
  }

  // Test draining the pool when there left 1-N buffers.
  std::vector<CameraBufferPool::Buffer> buffers;
  for (size_t i = 0; i < options.max_num_buffers; ++i) {
    for (size_t j = 0; j < options.max_num_buffers - i; ++j) {
      std::optional<CameraBufferPool::Buffer> buffer = pool.RequestBuffer();
      ASSERT_TRUE(buffer.has_value());
      ASSERT_NE(buffer->handle(), nullptr);
      buffers.push_back(*std::move(buffer));
    }
    ASSERT_FALSE(pool.RequestBuffer().has_value());
    for (size_t j = 0; j < options.max_num_buffers - i - 1; ++j) {
      buffers.pop_back();
    }
  }
}

TEST(CameraBufferPoolTest, DestroyBufferPoolInUse) {
  CameraBufferPool::Options options = {
      .width = 320,
      .height = 240,
      .format = HAL_PIXEL_FORMAT_YCbCr_420_888,
      .usage = 0,
      .max_num_buffers = 1,
  };
  // Holds a buffer that out-lives the pool.
  std::optional<CameraBufferPool::Buffer> buffer;
  ASSERT_DEATH(
      {
        CameraBufferPool pool(options);
        buffer = pool.RequestBuffer();
        ASSERT_TRUE(buffer.has_value());
      },
      "CameraBufferPool destructed when there's buffer in use");
}

}  // namespace cros

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
