/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_CAMERA_HAL_DEVICE_OPS_H_
#define CAMERA_HAL_FAKE_CAMERA_HAL_DEVICE_OPS_H_

#include <hardware/camera3.h>

namespace cros {

// Camera device operations handle shared by all devices. The operation of one
// device are called on the same mojo thread. The operations of two different
// devices are called on two different mojo threads.
extern camera3_device_ops_t g_camera_device_ops;

}  // namespace cros

#endif  // CAMERA_HAL_FAKE_CAMERA_HAL_DEVICE_OPS_H_
