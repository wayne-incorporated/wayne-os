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

#include <fcntl.h>
#include <linux/media.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <base/files/file_enumerator.h>

#include "cros-camera/common.h"

namespace cros {
V4L2Device::V4L2Device(const std::string name) : name_(name), fd_(-1) {}

V4L2Device::~V4L2Device() {
  if (IsOpened()) {
    LOGF(WARNING) << "Destroying a device object not closed, closing first";
    Close();
  }
}

int V4L2Device::Open(int flags) {
  if (IsOpened()) {
    LOGF(WARNING) << "Device is already opened";
    return 0;
  }

  struct stat st = {};
  if (stat(name_.c_str(), &st) == -1) {
    PLOGF(ERROR) << "Error stat video device " << name_;
    return -ENODEV;
  }
  if (!S_ISCHR(st.st_mode)) {
    LOGF(ERROR) << name_ << " is not a device";
    return -ENODEV;
  }

  fd_ = ::open(name_.c_str(), flags);
  if (fd_ < 0) {
    PLOGF(ERROR) << "Error opening video device " << name_;
    return -errno;
  }

  GetDescriptiveName();

  return 0;
}

int V4L2Device::Close() {
  if (!IsOpened()) {
    LOGF(WARNING) << "Device is not opened!";
    return -EINVAL;
  }

  int ret = ::close(fd_);
  if (ret < 0) {
    PLOGF(ERROR) << "Error closing video device " << descriptive_name_;
    return ret;
  }

  fd_ = -1;
  return 0;
}

int V4L2Device::SubscribeEvent(int event) {
  if (!IsOpened()) {
    LOGF(ERROR) << "Device " << descriptive_name_
                << " already closed. Do nothing.";
    return -1;
  }

  struct v4l2_event_subscription sub = {};
  sub.type = event;
  int ret = ::ioctl(fd_, VIDIOC_SUBSCRIBE_EVENT, &sub);
  if (ret < 0) {
    PLOGF(ERROR) << "Error subscribing event 0x" << std::hex << event;
    return ret;
  }

  return ret;
}

int V4L2Device::UnsubscribeEvent(int event) {
  if (!IsOpened()) {
    LOGF(ERROR) << "Device " << name_ << " already closed. Do nothing.";
    return -1;
  }

  struct v4l2_event_subscription sub = {};
  sub.type = event;

  int ret = ::ioctl(fd_, VIDIOC_UNSUBSCRIBE_EVENT, &sub);
  if (ret < 0) {
    PLOGF(ERROR) << "Error unsubscribing event 0x" << std::hex << event;
    return ret;
  }

  return ret;
}

int V4L2Device::DequeueEvent(struct v4l2_event* event) {
  if (!event) {
    return -EINVAL;
  }

  if (!IsOpened()) {
    LOGF(ERROR) << "Device " << name_ << " already closed. Do nothing.";
    return -1;
  }

  int ret = ::ioctl(fd_, VIDIOC_DQEVENT, event);
  if (ret < 0) {
    LOGF(ERROR) << "error dequeuing event";
    return ret;
  }

  return ret;
}

int V4L2Device::SetControl(struct v4l2_control* control) {
  if (!IsOpened()) {
    LOGF(ERROR) << "Invalid device state (CLOSED)";
    return -EINVAL;
  }
  if (!control) {
    LOGF(ERROR) << "Null pointer of control";
    return -EINVAL;
  }
  return ::ioctl(fd_, VIDIOC_S_CTRL, control);
}

int V4L2Device::SetControl(struct v4l2_ext_control* ext_control) {
  if (!IsOpened()) {
    LOGF(ERROR) << "Invalid device state (CLOSED)";
    return -EINVAL;
  }
  if (!ext_control) {
    LOGF(ERROR) << "Null pointer of ext_control";
    return -EINVAL;
  }
  struct v4l2_ext_controls controls = {};
  controls.ctrl_class = V4L2_CTRL_ID2CLASS(ext_control->id);
  controls.count = 1;
  controls.controls = ext_control;
  return ::ioctl(fd_, VIDIOC_S_EXT_CTRLS, &controls);
}

int V4L2Device::SetControl(int id, int32_t value) {
  VLOGF(2) << "Setting attribute " << id << " to " << value;
  int ret = 0;

  struct v4l2_ext_control ext_control = {};
  ext_control.id = id;
  ext_control.value = value;
  ret = SetControl(&ext_control);
  if (ret != 0) {
    PLOGF(ERROR) << "Failed to set value " << value << " for control " << id
                 << " on device " << descriptive_name_;
  }
  return ret;
}

int V4L2Device::SetControl(int id, int64_t value) {
  VLOGF(2) << "Setting attribute " << id << " to " << value;
  struct v4l2_ext_control ext_control = {};
  ext_control.id = id;
  ext_control.value64 = value;
  int ret = SetControl(&ext_control);
  if (ret != 0) {
    PLOGF(ERROR) << "Failed to set value " << value << " for control " << id
                 << " on device " << descriptive_name_;
  }
  return ret;
}

int V4L2Device::SetControl(int id, const std::string value) {
  VLOGF(2) << "Setting attribute " << id << " to " << value;
  struct v4l2_ext_control ext_control = {};
  ext_control.id = id;
  ext_control.string = const_cast<char*>(value.c_str());
  int ret = SetControl(&ext_control);
  if (ret != 0) {
    PLOGF(ERROR) << "Failed to set value " << value << " for control " << id
                 << " on device " << descriptive_name_;
  }
  return ret;
}

int V4L2Device::GetControl(struct v4l2_ext_control* ext_control) {
  if (!IsOpened()) {
    LOGF(ERROR) << "Invalid state device (CLOSED)";
    return -EINVAL;
  }
  struct v4l2_ext_controls controls = {};
  controls.ctrl_class = V4L2_CTRL_ID2CLASS(ext_control->id);
  controls.count = 1;
  controls.controls = ext_control;

  int ret = ::ioctl(fd_, VIDIOC_G_EXT_CTRLS, &controls);
  if (ret != 0) {
    PLOGF(ERROR) << "Failed to get value for control (" << ext_control->id
                 << ") on device " << descriptive_name_;
    return ret;
  }
  return 0;
}

int V4L2Device::GetControl(int id, int32_t* value) {
  if (!value) {
    return -EINVAL;
  }
  struct v4l2_ext_control ext_control = {};
  ext_control.id = id;
  int ret = GetControl(&ext_control);
  if (ret == 0) {
    *value = ext_control.value;
  }
  return ret;
}

int V4L2Device::GetControl(int id, int64_t* value) {
  if (!value) {
    return -EINVAL;
  }
  struct v4l2_ext_control ext_control = {};
  ext_control.id = id;
  int ret = GetControl(&ext_control);
  if (ret == 0) {
    *value = ext_control.value64;
  }
  return ret;
}

int V4L2Device::GetControl(int id, std::string* value) {
  if (!value) {
    return -EINVAL;
  }
  struct v4l2_ext_control ext_control = {};
  ext_control.id = id;
  int ret = GetControl(&ext_control);
  if (ret == 0) {
    *value = ext_control.string;
  }
  return ret;
}

int V4L2Device::QueryMenu(v4l2_querymenu* menu) {
  if (!menu) {
    return -EINVAL;
  }

  if (fd_ == -1) {
    LOGF(ERROR) << "Invalid state device (CLOSED)";
    return -EINVAL;
  }

  int ret = ::ioctl(fd_, VIDIOC_QUERYMENU, menu);
  if (ret != 0) {
    PLOGF(ERROR) << "Failed to get values for query menu (" << menu->id
                 << ") on device" << descriptive_name_;
  }
  return ret;
}

int V4L2Device::QueryControl(v4l2_queryctrl* control) {
  if (!control) {
    return -EINVAL;
  }

  if (fd_ == -1) {
    LOGF(ERROR) << "Invalid state device (CLOSED)";
    return -EINVAL;
  }

  int ret = ::ioctl(fd_, VIDIOC_QUERYCTRL, control);
  if (ret != 0) {
    PLOGF(ERROR) << "Failed to get values for query control (" << control->id
                 << ") on device " << descriptive_name_;
  }
  return ret;
}

void V4L2Device::GetDescriptiveName() {
  struct stat sb;

  descriptive_name_ = name_;

  // Try to get the descriptive name from media info.
  if (fstat(fd_, &sb) == 0) {
    base::FileEnumerator enumerator(base::FilePath("/dev"), false,
                                    base::FileEnumerator::FILES, "media*");

    for (base::FilePath target_path = enumerator.Next(); !target_path.empty();
         target_path = enumerator.Next()) {
      int fd = open(target_path.value().c_str(), O_RDWR | O_NONBLOCK);
      if (fd < 0) {
        continue;
      }
      base::ScopedFD media_fd(fd);

      struct media_entity_desc ent = {};
      ent.id = MEDIA_ENT_ID_FLAG_NEXT;
      while (::ioctl(media_fd.get(), MEDIA_IOC_ENUM_ENTITIES, &ent) == 0) {
        if (ent.dev.major == major(sb.st_rdev) &&
            ent.dev.minor == minor(sb.st_rdev)) {
          descriptive_name_ = descriptive_name_ + "(" + ent.name + ")";
          return;
        }
        ent.id |= MEDIA_ENT_ID_FLAG_NEXT;
      }
    }
  }

  // If we can't get debug name from media info, try to get card name.
  v4l2_capability cap = {};
  if (::ioctl(fd_, VIDIOC_QUERYCAP, &cap) == 0) {
    descriptive_name_ =
        descriptive_name_ + "(" + reinterpret_cast<char*>(cap.card) + ")";
    return;
  }
}

int V4L2Device::Poll(int timeout) {
  struct pollfd pfd = {0};
  int ret(0);

  if (fd_ == -1) {
    LOGF(ERROR) << "Device " << name_ << " already closed. Do nothing.";
    return -1;
  }

  pfd.fd = fd_;
  pfd.events = POLLPRI | POLLIN | POLLERR;

  ret = ::poll(&pfd, 1, timeout);

  if (ret < 0) {
    LOGF(ERROR) << "poll error ret=" << ret << ", mFd= " << fd_
                << ", error:" << strerror(errno);
    return ret;
  }

  if (pfd.revents & POLLERR) {
    LOGF(ERROR) << "received POLLERR";
    return -1;
  }

  return ret;
}

V4L2DevicePoller::V4L2DevicePoller(std::vector<V4L2Device*> devices,
                                   int flush_fd)
    : devices_(std::move(devices)),
      flush_fd_(flush_fd),
      poll_fds_(devices_.size() + ((flush_fd == -1) ? 0 : 1)) {
  for (size_t i = 0; i < devices_.size(); i++) {
    if (!devices_[i]) {
      LOGF(ERROR) << "Invalid device at index " << i;
      poll_fds_.resize(0);
      return;
    }
    poll_fds_[i].fd = devices_[i]->fd_;
    poll_fds_[i].revents = 0;
  }
  if (flush_fd_ != -1) {
    poll_fds_.back().fd = flush_fd_;
    poll_fds_.back().events = POLLIN | POLLPRI;
  }
}

int V4L2DevicePoller::Poll(int timeout_ms,
                           int events,
                           std::vector<V4L2Device*>* ready_devices) {
  if (poll_fds_.empty()) {
    return -EINVAL;
  }
  for (size_t i = 0; i < devices_.size(); i++) {
    poll_fds_[i].events = events;
  }
  int ret = ::poll(poll_fds_.data(), poll_fds_.size(), timeout_ms);
  if (ret <= 0) {
    for (size_t i = 0; i < devices_.size(); i++) {
      PLOGF(ERROR) << "Device " << devices_[i]->descriptive_name_
                   << " poll failed (" << ((ret == 0) ? "timeout)" : "error)");
    }
    return ret;
  }

  // check first the flush
  if (flush_fd_ != -1 && (poll_fds_.back().revents & (POLLIN | POLLPRI))) {
    VLOGF(1) << "Poll returning from flush";
    return ret;
  }

  bool is_pollerr = false;
  for (size_t i = 0; i < devices_.size(); i++) {
    if (poll_fds_[i].revents & POLLERR) {
      LOGF(ERROR) << "Device " << devices_[i]->name_ << " received POLLERR";
      is_pollerr = true;
    }
  }
  if (is_pollerr) {
    return -1;
  }

  if (ready_devices != nullptr) {
    // check other active devices.
    for (size_t i = 0; i < devices_.size(); i++) {
      // return nodes that have data available
      if (poll_fds_[i].revents & events) {
        ready_devices->push_back(devices_[i]);
      }
    }
  }
  return ret;
}
}  // namespace cros
