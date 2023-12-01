// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_RECORDING_FIXTURE_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_RECORDING_FIXTURE_H_

#include <deque>
#include <unordered_map>
#include <vector>

#include "camera3_test/camera3_preview_fixture.h"

namespace camera3_test {

class Camera3RecordingFixture : public Camera3PreviewFixture {
 public:
  explicit Camera3RecordingFixture(std::vector<int> cam_ids)
      : Camera3PreviewFixture(cam_ids), cam_ids_(cam_ids) {}
  Camera3RecordingFixture(const Camera3RecordingFixture&) = delete;
  Camera3RecordingFixture& operator=(const Camera3RecordingFixture&) = delete;

  void SetUp() override;

  // Process recording result. Tests can override this function to handle the
  // results to suit their purpose. Note that the metadata |metadata| will be
  // freed after returning from this call.
  virtual void ProcessRecordingResult(int cam_id,
                                      uint32_t frame_number,
                                      ScopedCameraMetadata metadata);

 protected:
  // Stores time at start of image sensor exposure in nanoseconds with camera
  // id as the index
  std::unordered_map<int, std::deque<int64_t>> sensor_timestamp_map_;

 private:
  std::vector<int> cam_ids_;
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_RECORDING_FIXTURE_H_
