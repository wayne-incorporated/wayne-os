// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SWAP_MANAGEMENT_SWAP_TOOL_STATUS_H_
#define SWAP_MANAGEMENT_SWAP_TOOL_STATUS_H_

#include <absl/status/status.h>

namespace swap_management {
// Helper function to translate errno to absl::status
// Copied and modified from google3/third_party/absl/status/status.cc.
absl::Status ErrnoToStatus(int error_number, absl::string_view message);

}  // namespace swap_management

#endif  // SWAP_MANAGEMENT_SWAP_TOOL_STATUS_H_
