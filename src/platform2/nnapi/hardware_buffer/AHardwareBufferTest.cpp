// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

// android/log.h contains __INTRODUCED_IN() macro and must be included before
// hardware_buffer.h
#include <android/log.h>
#include <vndk/hardware_buffer.h>

// Ensures we can link each of the functions implemented in AHardwareBuffer.cpp
TEST(AHardwareBufferTest, LinkTest) {
  AHardwareBuffer_allocate(nullptr, nullptr);
  AHardwareBuffer_createFromHandle(nullptr, nullptr, 0, nullptr);
  AHardwareBuffer_describe(nullptr, nullptr);
  AHardwareBuffer_getNativeHandle(nullptr);
  AHardwareBuffer_lock(nullptr, 0, 0, nullptr, nullptr);
  AHardwareBuffer_release(nullptr);
  AHardwareBuffer_unlock(nullptr, nullptr);
}
