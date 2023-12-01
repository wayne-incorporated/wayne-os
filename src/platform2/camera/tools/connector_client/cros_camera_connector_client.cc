/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <linux/videodev2.h>
#include <sysexits.h>

#include <cstring>
#include <string>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file.h>
#include <base/functional/bind.h>
#include <base/posix/safe_strerror.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/sequenced_task_runner.h>

#include "cros-camera/common.h"
#include "tools/connector_client/cros_camera_connector_client.h"

namespace {

std::string GetDrmFormatName(uint32_t fourcc) {
  std::string result = "0000";
  for (size_t i = 0; i < 4; i++, fourcc >>= 8) {
    const char c = static_cast<char>(fourcc & 0xFF);
    if (c <= 0x1f || c >= 0x7f) {
      return base::StringPrintf("0x%x", fourcc);
    }
    result[i] = c;
  }
  return result;
}

}  // namespace

namespace cros {

int OnGotCameraInfo(void* context,
                    const cros_cam_info_t* info,
                    int is_removed) {
  auto* client = reinterpret_cast<CrosCameraConnectorClient*>(context);

  if (is_removed) {
    client->RemoveCamera(info->id);
    return 0;
  }

  LOGF(INFO) << "Gotten camera info of " << info->id
             << " (name = " << info->name
             << ", format_count = " << info->format_count << ")";
  for (int i = 0; i < info->format_count; i++) {
    LOGF(INFO) << "format = " << GetDrmFormatName(info->format_info[i].fourcc)
               << ", width = " << info->format_info[i].width
               << ", height = " << info->format_info[i].height
               << ", fps = " << info->format_info[i].fps;
  }

  client->SetCamInfo(info);
  return 0;
}

int OnCaptureResultAvailable(void* context,
                             const cros_cam_capture_result_t* result) {
  static uint32_t frame_count = 0;

  auto* client = reinterpret_cast<CrosCameraConnectorClient*>(context);

  if (result->status != 0) {
    LOGF(ERROR) << "Received an error notification: "
                << base::safe_strerror(-result->status);
    if (result->status == -ENODEV) {
      LOGF(ERROR)
          << "Device encountered a serious error. Starting capture again";
      client->StartCapture();
    }
    return 0;
  }
  const cros_cam_frame_t* frame = result->frame;
  CHECK_NE(frame, nullptr);
  LOGF(INFO) << "Frame Available";

  client->ProcessFrame(frame);

  frame_count++;
  if (frame_count == 10) {
    frame_count = 0;
    LOGF(INFO) << "Restarting capture";
    client->RestartCapture();
  }
  return 0;
}

CrosCameraConnectorClient::CrosCameraConnectorClient()
    : client_runner_(base::SequencedTaskRunner::GetCurrentDefault()),
      init_done_(false),
      current_id_(-1),
      capture_thread_("CamConnClient"),
      num_restarts_(0) {}

int CrosCameraConnectorClient::OnInit() {
  int res = brillo::Daemon::OnInit();
  if (res != EX_OK) {
    return res;
  }

  if (!capture_thread_.Start()) {
    LOGF(FATAL) << "Failed to start capture thread";
  }

  const cros_cam_init_option_t option = {
      .api_version = 0,
  };
  res = cros_cam_init(&option);
  if (res != 0) {
    return EX_UNAVAILABLE;
  }

  res = cros_cam_get_cam_info(&OnGotCameraInfo, this);
  if (res != 0) {
    return EX_UNAVAILABLE;
  }
  init_done_ = true;

  CHECK(!camera_device_list_.empty());
  for (auto id : camera_device_list_) {
    auto& infos = format_info_map_[id];
    auto& pending_capture = pending_captures_map_[id];
    for (const auto& info : infos) {
      pending_capture.push(info);
    }
  }
  StartCapture();

  return EX_OK;
}

void CrosCameraConnectorClient::OnShutdown(int* exit_code) {
  capture_thread_.Stop();
  cros_cam_exit();
}

void CrosCameraConnectorClient::SetCamInfo(const cros_cam_info_t* info) {
  {
    base::AutoLock camera_info_lock(camera_info_lock_);
    base::AutoLock capture_lock(capture_lock_);
    auto& pending_captures = pending_captures_map_[info->id];
    pending_captures = {};
    for (int i = 0; i < info->format_count; i++) {
      pending_captures.push(info->format_info[i]);
    }
    if (std::find(camera_device_list_.begin(), camera_device_list_.end(),
                  info->id) == camera_device_list_.end()) {
      LOGF(INFO) << "Camera added: " << info->id;
      camera_device_list_.push_back(info->id);
    }
  }
  if (init_done_) {
    LOGF(INFO) << "Restarting capture";
    RestartCapture();
  }
}

void CrosCameraConnectorClient::RemoveCamera(int32_t id) {
  base::AutoLock camera_info_lock(camera_info_lock_);
  base::AutoLock capture_lock(capture_lock_);
  auto it =
      std::find(camera_device_list_.begin(), camera_device_list_.end(), id);
  CHECK(it != camera_device_list_.end());
  LOGF(INFO) << "Camera removed: " << (*it);
  camera_device_list_.erase(it);
  pending_captures_map_[id] = {};
}

void CrosCameraConnectorClient::ProcessFrame(const cros_cam_frame_t* frame) {
  static const char kJpegFilePattern[] = "/tmp/connector_#.jpg";
  static const char kNv12FilePattern[] = "/tmp/connector_#.yuv";
  static int frame_iter = 0;

  if (frame->format.fourcc == V4L2_PIX_FMT_MJPEG) {
    std::string output_path(kJpegFilePattern);
    base::ReplaceSubstringsAfterOffset(&output_path, /*start_offset=*/0, "#",
                                       base::StringPrintf("%06u", frame_iter));
    base::File file(base::FilePath(output_path),
                    base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
    file.WriteAtCurrentPos(reinterpret_cast<char*>(frame->planes[0].data),
                           frame->planes[0].size);
    LOGF(INFO) << "Saved JPEG: " << output_path
               << "  (size = " << frame->planes[0].size << ")";
  } else if (frame->format.fourcc == V4L2_PIX_FMT_NV12) {
    std::string output_path(kNv12FilePattern);
    base::ReplaceSubstringsAfterOffset(&output_path, /*start_offset=*/0, "#",
                                       base::StringPrintf("%06u", frame_iter));
    base::File file(base::FilePath(output_path),
                    base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
    file.WriteAtCurrentPos(
        reinterpret_cast<const char*>(frame->planes[0].data),
        current_format_info_.height * frame->planes[0].stride);
    file.WriteAtCurrentPos(
        reinterpret_cast<const char*>(frame->planes[1].data),
        (current_format_info_.height + 1) / 2 * frame->planes[1].stride);
    LOGF(INFO) << "Saved YUV (NV12): " << output_path;
  }

  frame_iter++;
}

void CrosCameraConnectorClient::StartCapture() {
  capture_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CrosCameraConnectorClient::StartCaptureOnThread,
                     base::Unretained(this)));
}

void CrosCameraConnectorClient::RestartCapture() {
  capture_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CrosCameraConnectorClient::RestartCaptureOnThread,
                     base::Unretained(this)));
}

void CrosCameraConnectorClient::StartCaptureOnThread() {
  CHECK(capture_thread_.task_runner()->BelongsToCurrentThread());

  {
    base::AutoLock capture_lock(capture_lock_);
    // TODO(b/151047930): Test the start/stop capture sequence with gtest.
    if (pending_captures_map_.empty()) {
      return;
    }
    auto it = pending_captures_map_.begin();
    while (it != pending_captures_map_.end() && it->second.empty()) {
      pending_captures_map_.erase(it);
      it = pending_captures_map_.begin();
    }
    if (it == pending_captures_map_.end()) {
      return;
    }
    current_id_ = it->first;
    current_format_info_ = it->second.front();
    it->second.pop();
    LOGF(INFO) << "Starting capture: device = " << current_id_
               << ", fourcc = " << GetDrmFormatName(current_format_info_.fourcc)
               << ", width = " << current_format_info_.width
               << ", height = " << current_format_info_.height
               << ", fps = " << current_format_info_.fps;
  }

  const cros_cam_capture_request_t request = {
      .id = current_id_,
      .format = &current_format_info_,
  };
  cros_cam_start_capture(&request, &OnCaptureResultAvailable, this);
}

void CrosCameraConnectorClient::StopCaptureOnThread() {
  CHECK(capture_thread_.task_runner()->BelongsToCurrentThread());
  base::AutoLock capture_lock(capture_lock_);

  cros_cam_stop_capture(current_id_);
  current_id_ = -1;
}

void CrosCameraConnectorClient::RestartCaptureOnThread() {
  CHECK(capture_thread_.task_runner()->BelongsToCurrentThread());
  ++num_restarts_;
  LOGF(INFO) << "Restarting capture #" << num_restarts_;
  StopCaptureOnThread();
  StartCaptureOnThread();
}

}  // namespace cros

int main() {
  cros::CrosCameraConnectorClient connector_client;
  return connector_client.Run();
}
