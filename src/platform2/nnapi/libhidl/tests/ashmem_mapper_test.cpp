// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <android/hidl/memory/1.0/IMapper.h>
#include <android/hidl/memory/1.0/IMemory.h>
#include <gtest/gtest.h>

using ::android::sp;
using ::android::hardware::hidl_memory;
using ::android::hidl::memory::V1_0::IMapper;
using ::android::hidl::memory::V1_0::IMemory;

TEST(AshmemMapperTest, EmptyMemory) {
  auto mapper = IMapper::getService("ashmem", false);
  ASSERT_NE(nullptr, mapper);
}
