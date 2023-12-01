/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/camera_privacy_switch_monitor.h"

#include <fcntl.h>
#include <linux/videodev2.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <utility>

#include <base/files/file_util.h>

#include "cros-camera/common.h"

namespace cros {

namespace {

int GetControlValue(int device_fd, int32_t* value) {
  v4l2_control current = {.id = static_cast<__u32>(V4L2_CID_PRIVACY)};
  int ret = HANDLE_EINTR(ioctl(device_fd, VIDIOC_G_CTRL, &current));
  if (ret < 0) {
    ret = ERRNO_OR_RET(ret);
    PLOGF(ERROR) << "Failed to get privacy control value";
    return ret;
  }
  *value = current.value;
  return 0;
}

bool IsControlAvailable(int device_fd) {
  v4l2_queryctrl query_ctrl = {.id = static_cast<__u32>(V4L2_CID_PRIVACY)};
  if (HANDLE_EINTR(ioctl(device_fd, VIDIOC_QUERYCTRL, &query_ctrl)) < 0) {
    VLOGF(1) << "Privacy control unsupported";
    return false;
  }
  if (query_ctrl.flags & V4L2_CTRL_FLAG_DISABLED) {
    VLOGF(1) << "Privacy control is disabled";
    return false;
  }
  return true;
}

}  // namespace

CameraPrivacySwitchMonitor::CameraPrivacySwitchMonitor()
    : state_(PrivacySwitchState::kUnknown), event_thread_("V4L2Event") {}

CameraPrivacySwitchMonitor::~CameraPrivacySwitchMonitor() {
  UnsubscribeEvents();
}

void CameraPrivacySwitchMonitor::RegisterCallback(
    PrivacySwitchStateChangeCallback callback) {
  callback_ = std::move(callback);

  base::AutoLock l(camera_id_lock_);
  for (const auto& it : subscribed_camera_id_to_fd_) {
    int camera_id = it.first;

    int32_t cur_value;
    if (GetControlValue(it.second.get(), &cur_value) != 0) {
      LOGF(ERROR)
          << "Failed to get current value of privacy control for camera: "
          << camera_id;
      continue;
    }
    OnStatusChanged(camera_id, cur_value != 0 ? PrivacySwitchState::kOn
                                              : PrivacySwitchState::kOff);
  }
}

void CameraPrivacySwitchMonitor::TrySubscribe(int camera_id,
                                              const std::string& device_path) {
  {
    base::AutoLock l(camera_id_lock_);
    if (subscribed_camera_id_to_fd_.find(camera_id) !=
        subscribed_camera_id_to_fd_.end()) {
      // The camera id is already subscribed.
      return;
    }
  }

  base::ScopedFD device_fd(
      TEMP_FAILURE_RETRY(open(device_path.c_str(), O_RDWR)));
  if (!device_fd.is_valid()) {
    LOGF(ERROR) << "Failed to open " << device_path;
    return;
  }

  if (!IsControlAvailable(device_fd.get())) {
    return;
  }

  int32_t init_value;
  if (GetControlValue(device_fd.get(), &init_value) != 0) {
    LOGF(ERROR) << "Failed to get initial value of privacy control for camera: "
                << camera_id;
    return;
  }
  OnStatusChanged(camera_id, init_value != 0 ? PrivacySwitchState::kOn
                                             : PrivacySwitchState::kOff);
  SubscribeEvent(camera_id, std::move(device_fd));
}

void CameraPrivacySwitchMonitor::Unsubscribe(int camera_id) {
  base::AutoLock l(camera_id_lock_);
  auto it = subscribed_camera_id_to_fd_.find(camera_id);
  if (it == subscribed_camera_id_to_fd_.end()) {
    return;
  }
  subscribed_camera_id_to_fd_.erase(it);

  RestartEventLoop();
}

void CameraPrivacySwitchMonitor::OnStatusChanged(int camera_id,
                                                 PrivacySwitchState state) {
  if (state == state_) {
    return;
  }

  state_ = state;
  if (!callback_.is_null()) {
    callback_.Run(camera_id, state);
  }
}

void CameraPrivacySwitchMonitor::SubscribeEvent(int camera_id,
                                                base::ScopedFD device_fd) {
  struct v4l2_event_subscription sub = {.type = V4L2_EVENT_CTRL,
                                        .id = V4L2_CID_PRIVACY};
  if (HANDLE_EINTR(ioctl(device_fd.get(), VIDIOC_SUBSCRIBE_EVENT, &sub)) < 0) {
    PLOGF(ERROR) << "Failed to subscribe for privacy status change";
    return;
  }
  base::AutoLock l(camera_id_lock_);
  subscribed_camera_id_to_fd_.emplace(camera_id, std::move(device_fd));

  // If the thread hasn't been started, start the thread to listen for events.
  // If the thread is already started, triggers the thread to make it restart
  // so that it can listen for the new fd.
  if (event_thread_.IsRunning()) {
    RestartEventLoop();
  } else {
    if (!event_thread_.Start()) {
      LOGF(ERROR) << "Failed to start V4L2 event thread";
      return;
    }

    if (!base::CreatePipe(&control_fd_, &control_pipe_, true)) {
      LOGF(ERROR) << "Failed to create the control pipe";
      return;
    }

    event_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindRepeating(&CameraPrivacySwitchMonitor::RunDequeueEventsLoop,
                            base::Unretained(this)));
  }
}

void CameraPrivacySwitchMonitor::UnsubscribeEvents() {
  control_pipe_.reset();
  if (event_thread_.IsRunning()) {
    event_thread_.Stop();
  }

  base::AutoLock l(camera_id_lock_);
  for (auto& it : subscribed_camera_id_to_fd_) {
    struct v4l2_event_subscription sub = {.type = V4L2_EVENT_CTRL,
                                          .id = V4L2_CID_PRIVACY};
    if (HANDLE_EINTR(ioctl(it.second.get(), VIDIOC_UNSUBSCRIBE_EVENT, &sub)) <
        0) {
      PLOGF(ERROR) << "Failed to unsubscribe for privacy status change";
    }
  }
  subscribed_camera_id_to_fd_.clear();
}

void CameraPrivacySwitchMonitor::RunDequeueEventsLoop() {
  while (true) {
    std::vector<struct pollfd> fds;
    std::vector<int> camera_ids;
    {
      base::AutoLock l(camera_id_lock_);
      for (const auto& it : subscribed_camera_id_to_fd_) {
        camera_ids.push_back(it.first);
        fds.push_back({it.second.get(), POLLPRI, 0});
      }
      fds.push_back({control_fd_.get(), POLLIN | POLLHUP, 0});
    }

    if (HANDLE_EINTR(poll(fds.data(), fds.size(), -1)) <= 0) {
      LOGF(ERROR) << "Failed to poll to dequeue events";
      return;
    }

    if (fds.back().revents & POLLHUP) {
      control_fd_.reset();
      return;
    }

    for (size_t i = 0; i < camera_ids.size(); i++) {
      if (fds[i].revents > 0) {
        struct v4l2_event ev = {};
        if (HANDLE_EINTR(ioctl(fds[i].fd, VIDIOC_DQEVENT, &ev)) < 0) {
          PLOGF(ERROR) << "Failed to dequeue event from device";
          // Unsubscribe camera if it is not unsubscribed for unknown reasons.
          // This issue was observed on Whiterun devices. Ref: b/269989471
          if (errno == ENODEV) {
            Unsubscribe(camera_ids[i]);
          }
          continue;
        }

        if (ev.type == V4L2_EVENT_CTRL && ev.id == V4L2_CID_PRIVACY) {
          OnStatusChanged(camera_ids[i], ev.u.ctrl.value != 0
                                             ? PrivacySwitchState::kOn
                                             : PrivacySwitchState::kOff);
        }
      }
    }

    // If there is some data in |control_pipe| which is used to trigger the
    // restart of the blocking loop, clear the data before restarting.
    if (fds.back().revents & POLLIN) {
      uint8_t buf;
      if (read(fds.back().fd, &buf, sizeof(buf)) < 0) {
        PLOGF(ERROR) << "Failed to read data from control pipe";
      }
    }
  }
}

void CameraPrivacySwitchMonitor::RestartEventLoop() {
  uint8_t value = 0;
  if (write(control_pipe_.get(), &value, sizeof(value)) < 0) {
    PLOGF(ERROR) << "Failed to restart the event loop";
  }
}

}  // namespace cros
