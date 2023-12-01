// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <AshmemAllocator.h>
#include <hidl/HidlSupport.h>

#include <string>

namespace android {
namespace hidl {
namespace allocator {
namespace V1_0 {

// static
::android::sp<IAllocator> IAllocator::getService(const std::string& /*type*/,
                                                 bool /*getStub*/) {
  return new implementation::AshmemAllocator;
}

}  // namespace V1_0
}  // namespace allocator
}  // namespace hidl
}  // namespace android
