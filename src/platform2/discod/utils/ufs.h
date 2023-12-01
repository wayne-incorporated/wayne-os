// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_UTILS_UFS_H_
#define DISCOD_UTILS_UFS_H_

#include <optional>

#include <base/files/file_path.h>

namespace discod {

bool IsUfs(const base::FilePath& root_device, const base::FilePath& root);
bool IsWriteBoosterSupported(const base::FilePath& root_device,
                             const base::FilePath& root);
base::FilePath GetUfsDeviceNode(const base::FilePath& root_device,
                                const base::FilePath& root);
base::FilePath GetUfsWriteBoosterNode(const base::FilePath& root_device,
                                      const base::FilePath& root);

}  // namespace discod

#endif  // DISCOD_UTILS_UFS_H_
