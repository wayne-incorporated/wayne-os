// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "camera3_test/camera3_perf_log.h"

#include <inttypes.h>

#include <numeric>
#include <optional>

#include <base/command_line.h>
#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/strings/stringprintf.h>

#include "cros-camera/common.h"

namespace camera3_test {

// static
Camera3PerfLog* Camera3PerfLog::GetInstance() {
  static Camera3PerfLog perf;
  return &perf;
}

Camera3PerfLog::~Camera3PerfLog() {
  if (!base::CommandLine::ForCurrentProcess()->HasSwitch("output_log"))
    return;

  VLOGF(1) << "Outputing to log file: "
           << base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
                  "output_log");
  base::FilePath file_path(
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          "output_log"));
  if (base::WriteFile(file_path, NULL, 0) < 0) {
    LOGF(ERROR) << "Error writing to file " << file_path.value();
    return;
  }

  for (const auto& cam_id_name : camera_name_map_) {
    const std::string s =
        base::StringPrintf("Camera: %s\n", cam_id_name.second.c_str());
    base::AppendToFile(file_path, s);
    const std::vector<std::pair<std::string, int64_t>> perf_logs =
        CollectPerfLogs(cam_id_name.first);
    for (const auto& perf_log : perf_logs) {
      const std::string s = base::StringPrintf(
          "%s: %" PRId64 " us\n", perf_log.first.c_str(), perf_log.second);
      base::AppendToFile(file_path, s);
    }
  }
}

void Camera3PerfLog::SetCameraNameMap(
    const std::map<int, std::string>& camera_name_map) {
  camera_name_map_ = camera_name_map;
}

std::string Camera3PerfLog::GetCameraNameForId(int id) {
  auto it = camera_name_map_.find(id);
  return it != camera_name_map_.end() ? it->second : std::to_string(id);
}

bool Camera3PerfLog::UpdateDeviceEvent(int cam_id,
                                       DeviceEvent event,
                                       base::TimeTicks time) {
  VLOGF(1) << "Updating device event " << static_cast<int>(event)
           << " of camera " << cam_id << " at " << time << " us";
  if (base::Contains(device_events_[cam_id], event)) {
    LOGF(WARNING) << "Device event " << static_cast<int>(event) << " of camera "
                  << cam_id << " is being updated multiple times";
    return false;
  }
  device_events_[cam_id][event] = time;
  return true;
}

bool Camera3PerfLog::UpdateFrameEvent(int cam_id,
                                      uint32_t frame_number,
                                      FrameEvent event,
                                      base::TimeTicks time) {
  VLOGF(1) << "Updating frame event " << static_cast<int>(event)
           << " of camera " << cam_id << " for frame number " << frame_number
           << " at " << time << " us";
  if (base::Contains(frame_events_[cam_id][frame_number], event)) {
    LOGF(WARNING) << "Frame event " << static_cast<int>(event) << " of camera "
                  << cam_id << " frame number " << frame_number
                  << " is being updated multiple times";
    return false;
  }
  frame_events_[cam_id][frame_number][event] = time;
  return true;
}

std::vector<std::pair<std::string, int64_t>> Camera3PerfLog::CollectPerfLogs(
    int cam_id) const {
  std::vector<std::pair<std::string, int64_t>> perf_logs;

  // Collect perf logs from device events.
  constexpr std::pair<DeviceEvent, const char*> kDeviceEventNameMap[] = {
      {DeviceEvent::OPENED, "device_open"},
      {DeviceEvent::PREVIEW_STARTED, "preview_start"},
  };
  if (base::Contains(device_events_, cam_id)) {
    const std::map<DeviceEvent, base::TimeTicks>& events =
        device_events_.at(cam_id);
    if (!base::Contains(events, DeviceEvent::OPENING)) {
      LOGF(ERROR) << "Failed to find device opening performance log";
      return perf_logs;
    }
    const base::TimeTicks start_ticks = events.at(DeviceEvent::OPENING);
    for (const auto& event_name : kDeviceEventNameMap) {
      if (!base::Contains(events, event_name.first))
        continue;
      const base::TimeTicks end_ticks = events.at(event_name.first);
      perf_logs.emplace_back(event_name.second,
                             (end_ticks - start_ticks).InMicroseconds());
    }

    // The first still image captured time.
    if (base::Contains(frame_events_, cam_id)) {
      const auto it = std::find_if(
          frame_events_.at(cam_id).begin(), frame_events_.at(cam_id).end(),
          [](const auto& fn_events) {
            return base::Contains(fn_events.second,
                                  FrameEvent::STILL_CAPTURE_RESULT);
          });
      if (it != frame_events_.at(cam_id).end()) {
        const base::TimeTicks end_ticks =
            it->second.at(FrameEvent::STILL_CAPTURE_RESULT);
        perf_logs.emplace_back("still_image_capture",
                               (end_ticks - start_ticks).InMicroseconds());
      }
    }
  }

  // Collect perf logs from frame events.
  constexpr std::pair<FrameEvent, const char*> kFrameEventNameMap[] = {
      {FrameEvent::PREVIEW_RESULT, "preview_latency"},
      {FrameEvent::STILL_CAPTURE_RESULT, "still_capture_latency"},
      {FrameEvent::VIDEO_RECORD_RESULT, "video_record_latency"},
  };
  std::map<std::string, std::vector<int64_t>> frame_perf_logs;
  if (base::Contains(frame_events_, cam_id)) {
    for (const auto& it : frame_events_.at(cam_id)) {
      const uint32_t frame_number = it.first;
      const std::map<FrameEvent, base::TimeTicks>& events = it.second;
      if (!base::Contains(events, FrameEvent::SHUTTER)) {
        VLOGF(1) << "No shutter event found for frame " << frame_number
                 << " of camera " << cam_id;
        continue;
      }
      const base::TimeTicks start_ticks = events.at(FrameEvent::SHUTTER);
      for (const auto& event_name : kFrameEventNameMap) {
        if (!base::Contains(events, event_name.first))
          continue;
        const base::TimeTicks end_ticks = events.at(event_name.first);
        frame_perf_logs[event_name.second].push_back(
            (end_ticks - start_ticks).InMicroseconds());
      }
    }
    for (const auto& event_name : kFrameEventNameMap) {
      if (!base::Contains(frame_perf_logs, event_name.second))
        continue;
      const std::vector<int64_t>& logs = frame_perf_logs.at(event_name.second);
      if (!logs.empty()) {
        VLOGF(1) << "Calculate " << event_name.second << " from " << logs.size()
                 << " frames";
        perf_logs.emplace_back(
            event_name.second,
            std::accumulate(logs.begin(), logs.end(), 0) / logs.size());
      }
    }

    // Still capture shot to shot times.
    std::vector<int64_t> logs;
    std::optional<base::TimeTicks> start_ticks;
    for (const auto& it : frame_events_.at(cam_id)) {
      if (!base::Contains(it.second, FrameEvent::STILL_CAPTURE_RESULT))
        continue;
      const base::TimeTicks end_ticks =
          it.second.at(FrameEvent::STILL_CAPTURE_RESULT);
      if (start_ticks)
        logs.push_back((end_ticks - *start_ticks).InMicroseconds());
      start_ticks.emplace(end_ticks);
    }
    if (!logs.empty()) {
      VLOGF(1) << "Calculate shot_to_shot time from " << logs.size()
               << " samples";
      perf_logs.emplace_back(
          "shot_to_shot",
          std::accumulate(logs.begin(), logs.end(), 0) / logs.size());
    }

    // Portrait mode time.
    for (const auto& it : frame_events_.at(cam_id)) {
      if (!base::Contains(it.second, FrameEvent::PORTRAIT_MODE_STARTED) ||
          !base::Contains(it.second, FrameEvent::PORTRAIT_MODE_ENDED))
        continue;
      const base::TimeTicks start_ticks =
          it.second.at(FrameEvent::PORTRAIT_MODE_STARTED);
      const base::TimeTicks end_ticks =
          it.second.at(FrameEvent::PORTRAIT_MODE_ENDED);
      perf_logs.emplace_back("portrait_mode",
                             (end_ticks - start_ticks).InMicroseconds());
      break;
    }
  }

  return perf_logs;
}

}  // namespace camera3_test
