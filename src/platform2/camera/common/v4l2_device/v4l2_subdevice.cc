/*
 * Copyright (C) 2013-2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-camera/v4l2_device.h"

#include <sys/ioctl.h>

#include "cros-camera/common.h"

namespace cros {

V4L2Subdevice::V4L2Subdevice(const std::string name)
    : V4L2Device(name), state_(SubdevState::CLOSED) {}

V4L2Subdevice::~V4L2Subdevice() {
  {
    base::AutoLock l(state_lock_);
    if (state_ == SubdevState::CLOSED) {
      return;
    }
  }
  Close();
}

int V4L2Subdevice::Open(int flags) {
  base::AutoLock l(state_lock_);
  int status = V4L2Device::Open(flags);
  if (status == 0)
    state_ = SubdevState::OPEN;
  return status;
}

int V4L2Subdevice::Close() {
  base::AutoLock l(state_lock_);
  int status = V4L2Device::Close();
  state_ = (status == 0) ? SubdevState::CLOSED : SubdevState::ERROR;
  return status;
}

int V4L2Subdevice::SetFormat(const struct v4l2_subdev_format& format) {
  base::AutoLock l(state_lock_);
  if ((state_ != SubdevState::OPEN) && (state_ != SubdevState::CONFIGURED)) {
    LOGF(ERROR) << "Invalid device state " << static_cast<int>(state_);
    return -EINVAL;
  }

  VLOGF(1) << "VIDIOC_SUBDEV_S_FMT:"
           << "    pad:" << format.pad << "    which:" << format.which
           << "    width:" << format.format.width
           << "    height:" << format.format.height << "    format:0x"
           << std::hex << format.format.code << "    field:" << std::dec
           << format.format.field
           << "    color space:" << format.format.colorspace;

  int ret = ::ioctl(fd_, VIDIOC_SUBDEV_S_FMT, &format);
  if (ret < 0) {
    PLOGF(ERROR) << "VIDIOC_SUBDEV_S_FMT failed";
    return -EINVAL;
  }

  VLOGF(2) << "VIDIOC_SUBDEV_S_FMT:"
           << "    pad:" << format.pad << "    which:" << format.which
           << "    width:" << format.format.width
           << "    height:" << format.format.height << "    format:0x"
           << std::hex << format.format.code << "    field:" << std::dec
           << format.format.field
           << "    color space:" << format.format.colorspace;

  state_ = SubdevState::CONFIGURED;
  return 0;
}

int V4L2Subdevice::GetFormat(struct v4l2_subdev_format* format) {
  base::AutoLock l(state_lock_);
  if ((state_ != SubdevState::OPEN) && (state_ != SubdevState::CONFIGURED)) {
    LOGF(ERROR) << "Invalid device state " << static_cast<int>(state_);
    return -EINVAL;
  }

  int ret = ::ioctl(fd_, VIDIOC_SUBDEV_G_FMT, format);
  if (ret < 0) {
    PLOGF(ERROR) << "VIDIOC_SUBDEV_G_FMT failed";
    return -EINVAL;
  }

  VLOGF(1) << "VIDIOC_SUBDEV_G_FMT:"
           << "    pad:" << format->pad << "    which:" << format->which
           << "    width:" << format->format.width
           << "    height:" << format->format.height << "    format:0x"
           << std::hex << format->format.code << "    field:" << std::dec
           << format->format.field
           << "    color space:" << format->format.colorspace;

  return 0;
}

int V4L2Subdevice::GetPadFormat(int pad_index,
                                int* width,
                                int* height,
                                int* code) {
  if (!width || !height || !code) {
    return -EINVAL;
  }
  struct v4l2_subdev_format format = {};

  format.pad = pad_index;
  format.which = V4L2_SUBDEV_FORMAT_ACTIVE;
  int ret = GetFormat(&format);
  if (ret == 0) {
    *width = format.format.width;
    *height = format.format.height;
    *code = format.format.code;
  }
  return ret;
}

int V4L2Subdevice::SetSelection(const struct v4l2_subdev_selection& selection) {
  base::AutoLock l(state_lock_);
  if ((state_ != SubdevState::OPEN) && (state_ != SubdevState::CONFIGURED)) {
    LOGF(ERROR) << "Invalid device state " << static_cast<int>(state_);
    return -EINVAL;
  }

  VLOGF(1) << "VIDIOC_SUBDEV_S_SELECTION:"
           << "    which:" << selection.which << "    pad:" << selection.pad
           << "    target:" << std::hex << selection.target
           << "    flags:" << selection.flags << "    left:" << std::dec
           << selection.r.left << "    top:" << selection.r.top
           << "    width:" << selection.r.width
           << "    height:" << selection.r.height;

  int ret = ::ioctl(fd_, VIDIOC_SUBDEV_S_SELECTION, &selection);
  if (ret < 0) {
    PLOGF(ERROR) << "VIDIOC_SUBDEV_S_SELECTION failed";
  }
  return ret;
}

}  // namespace cros
