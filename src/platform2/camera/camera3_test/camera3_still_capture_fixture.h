// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_STILL_CAPTURE_FIXTURE_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_STILL_CAPTURE_FIXTURE_H_

#include <semaphore.h>
#include <stdio.h>

#include <unordered_map>
#include <vector>

#include "camera3_test/camera3_exif_validator.h"
#include "camera3_test/camera3_preview_fixture.h"

namespace camera3_test {

class Camera3StillCaptureFixture : public Camera3PreviewFixture {
 public:
  explicit Camera3StillCaptureFixture(std::vector<int> cam_ids)
      : Camera3PreviewFixture(cam_ids), cam_ids_(cam_ids) {}
  Camera3StillCaptureFixture(const Camera3StillCaptureFixture&) = delete;
  Camera3StillCaptureFixture& operator=(const Camera3StillCaptureFixture&) =
      delete;

  void SetUp() override;

  // Process still capture result metadata and output buffer. Tests can
  // override this function to handle the results to suit their purpose. Note
  // that the metadata |metadata| and output buffer |buffer| will be freed
  // after returning from this call.
  virtual void ProcessStillCaptureResult(int cam_id,
                                         uint32_t frame_number,
                                         ScopedCameraMetadata metadata,
                                         cros::ScopedBufferHandle buffer);

  // Wait for still capture result with timeout
  int WaitStillCaptureResult(int cam_id, const struct timespec& timeout);

 protected:
  using JpegExifInfo = Camera3ExifValidator::JpegExifInfo;

  struct StillCaptureResult {
    sem_t capture_result_sem;

    std::vector<ScopedCameraMetadata> result_metadatas;

    std::vector<time_t> result_date_time;

    std::vector<cros::ScopedBufferHandle> buffer_handles;

    StillCaptureResult();

    ~StillCaptureResult();
  };

  std::unordered_map<int, StillCaptureResult> still_capture_results_;

  // Max JPEG size with camera device id as the index
  std::unordered_map<int, size_t> jpeg_max_sizes_;

 private:
  std::vector<int> cam_ids_;
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_STILL_CAPTURE_FIXTURE_H_
