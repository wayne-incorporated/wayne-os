/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_LIBCAMERA_CONNECTOR_TYPES_H_
#define CAMERA_COMMON_LIBCAMERA_CONNECTOR_TYPES_H_

#include <base/functional/callback.h>

namespace cros {

using IntOnceCallback = base::OnceCallback<void(int)>;

}  // namespace cros

#endif  // CAMERA_COMMON_LIBCAMERA_CONNECTOR_TYPES_H_
