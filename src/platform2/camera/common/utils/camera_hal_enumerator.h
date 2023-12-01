/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_UTILS_CAMERA_HAL_ENUMERATOR_H_
#define CAMERA_COMMON_UTILS_CAMERA_HAL_ENUMERATOR_H_

#include <vector>

#include <base/files/file_path.h>

namespace cros {

std::vector<base::FilePath> GetCameraHalPaths();

}  // namespace cros

#endif  // CAMERA_COMMON_UTILS_CAMERA_HAL_ENUMERATOR_H_
