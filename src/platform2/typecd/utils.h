// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_UTILS_H_
#define TYPECD_UTILS_H_

#include <base/files/file_path.h>

namespace typecd {

// Helper function to parse Hex values from sysfs file paths.
// On success, the argument |*val| is updated with the value read.
//
// Returns:
//   True on success, False otherwise.
bool ReadHexFromPath(const base::FilePath& path, uint32_t* val);

}  // namespace typecd

#endif  // TYPECD_UTILS_H_
