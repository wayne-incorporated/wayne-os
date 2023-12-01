// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_PERF_LOG_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_PERF_LOG_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/time/time.h>

namespace camera3_test {

enum class DeviceEvent {
  OPENING,
  OPENED,
  PREVIEW_STARTED,
};

enum class FrameEvent {
  SHUTTER,
  PREVIEW_RESULT,
  STILL_CAPTURE_RESULT,
  VIDEO_RECORD_RESULT,
  PORTRAIT_MODE_STARTED,
  PORTRAIT_MODE_ENDED,
};

class Camera3PerfLog {
 public:
  Camera3PerfLog(const Camera3PerfLog&) = delete;
  Camera3PerfLog& operator=(const Camera3PerfLog&) = delete;

  // Gets the singleton instance
  static Camera3PerfLog* GetInstance();

  void SetCameraNameMap(const std::map<int, std::string>& camera_name_map);

  // Update one-time performance log
  bool UpdateDeviceEvent(int cam_id, DeviceEvent event, base::TimeTicks time);

  // Update per-frame performance log
  bool UpdateFrameEvent(int cam_id,
                        uint32_t frame_number,
                        FrameEvent event,
                        base::TimeTicks time);

 private:
  Camera3PerfLog() = default;

  ~Camera3PerfLog();

  // Get the camera name for a specific camera id, and fallback to "{id}" if not
  // found in the map
  std::string GetCameraNameForId(int id);

  std::vector<std::pair<std::string, int64_t>> CollectPerfLogs(
      int cam_id) const;

  // The name used for output log for each id
  std::map<int, std::string> camera_name_map_;

  // Record one-time performance logs with camera id and device event
  std::map<int, std::map<DeviceEvent, base::TimeTicks>> device_events_;

  // Record per-frame performance logs with camera id and frame event
  std::map<int, std::map<uint32_t, std::map<FrameEvent, base::TimeTicks>>>
      frame_events_;
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_PERF_LOG_H_
