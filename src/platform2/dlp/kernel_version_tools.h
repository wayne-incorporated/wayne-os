// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef DLP_KERNEL_VERSION_TOOLS_H_
#define DLP_KERNEL_VERSION_TOOLS_H_

#include <utility>

namespace dlp {

// Min kernel version that supports FAN_REPORT_FID and FAN_DELETE_SELF.
constexpr std::pair<int, int> kMinKernelVersionForFanDeleteEvents =
    std::make_pair(5, 1);

// Min kernel version that supports FAN_MARK_FILESYSTEM.
constexpr std::pair<int, int> kMinKernelVersionForFanMarkFilesystem =
    std::make_pair(4, 20);

// Returns the current kernel version. If there is a failure to retrieve the
// version, it returns <INT_MIN, INT_MIN>.
std::pair<int, int> GetKernelVersion();

}  // namespace dlp

#endif  // DLP_KERNEL_VERSION_TOOLS_H_
