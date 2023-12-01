// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// An implementation of the subset of hardware buffers functionality required by
// NNAPI. The upstream implementation of hardware buffers can be found in the
// AOSP source file frameworks/native/libs/nativewindow/AHardwareBuffer.cpp. See
// https://android.googlesource.com/platform/frameworks/native/+/HEAD/libs/nativewindow/AHardwareBuffer.cpp

// Unused functions are left without any implementations. Should a future
// version of NNAPI need a new function, we will be notified through a link
// error.

// android/log.h contains __INTRODUCED_IN() macro and must be included before
// hardware_buffer.h
#include <android/log.h>
#include <vndk/hardware_buffer.h>

int AHardwareBuffer_allocate(const AHardwareBuffer_Desc* /*desc*/,
                             AHardwareBuffer** /*outBuffer*/) {
  return 0;
}

int AHardwareBuffer_createFromHandle(const AHardwareBuffer_Desc* /*desc*/,
                                     const native_handle_t* /*handle*/,
                                     int32_t /*method*/,
                                     AHardwareBuffer** /*outBuffer*/) {
  return 0;
}

void AHardwareBuffer_describe(const AHardwareBuffer* /*buffer*/,
                              AHardwareBuffer_Desc* /*outDesc*/) {}

const native_handle_t* AHardwareBuffer_getNativeHandle(
    const AHardwareBuffer* /*buffer*/) {
  return nullptr;
}

int AHardwareBuffer_lock(AHardwareBuffer* /*buffer*/,
                         uint64_t /*usage*/,
                         int32_t /*fence*/,
                         const ARect* /*rect*/,
                         void** /*outVirtualAddress*/) {
  return 0;
}

void AHardwareBuffer_release(AHardwareBuffer* /*buffer*/) {}

int AHardwareBuffer_unlock(AHardwareBuffer* /*buffer*/, int32_t* /*fence*/) {
  return 0;
}
