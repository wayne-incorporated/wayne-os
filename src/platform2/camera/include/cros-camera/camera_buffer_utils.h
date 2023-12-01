/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CAMERA_BUFFER_UTILS_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CAMERA_BUFFER_UTILS_H_

#include <base/files/file_path.h>
#include <cutils/native_handle.h>

#include "cros-camera/export.h"

namespace cros {

bool CROS_CAMERA_EXPORT ReadFileIntoBuffer(buffer_handle_t buffer,
                                           base::FilePath file_to_read);

bool CROS_CAMERA_EXPORT WriteBufferIntoFile(buffer_handle_t buffer,
                                            base::FilePath file_to_write);

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_CAMERA_BUFFER_UTILS_H_
