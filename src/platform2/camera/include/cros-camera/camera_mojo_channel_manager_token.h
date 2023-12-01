/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CAMERA_MOJO_CHANNEL_MANAGER_TOKEN_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CAMERA_MOJO_CHANNEL_MANAGER_TOKEN_H_

#include "cros-camera/export.h"

namespace cros {

class CROS_CAMERA_EXPORT CameraMojoChannelManagerToken {
 public:
  static CameraMojoChannelManagerToken* CreateInstance();
  virtual ~CameraMojoChannelManagerToken() {}
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_CAMERA_MOJO_CHANNEL_MANAGER_TOKEN_H_
