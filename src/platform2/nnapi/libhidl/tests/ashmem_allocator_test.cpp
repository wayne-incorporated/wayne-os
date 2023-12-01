// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <android/hidl/allocator/1.0/IAllocator.h>
#include <gtest/gtest.h>

using ::android::hardware::hidl_memory;
using ::android::hidl::allocator::V1_0::IAllocator;

// TODO(slangley): Update test when the allocator is implemented.
TEST(SharedPointerAllocatorTest, Allocate) {
  auto allocator = IAllocator::getService("ashmem");
  hidl_memory memory;
  allocator->allocate(1024, [&](bool success, const hidl_memory& mem) {
    ASSERT_TRUE(success);
    memory = mem;
  });
  ASSERT_TRUE(memory.valid());
  ASSERT_EQ(1024, memory.size());
}
