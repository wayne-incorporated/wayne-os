// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <AshmemMapper.h>
#include <string>

namespace android {
namespace hidl {
namespace memory {
namespace V1_0 {

// static
sp<IMapper> IMapper::getService(const std::string&, bool) {
  return new implementation::AshmemMapper;
}

}  // namespace V1_0
}  // namespace memory
}  // namespace hidl
}  // namespace android
