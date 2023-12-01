/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_AUTO_FRAMING_TESTS_AUTO_FRAMING_TEST_FIXTURE_H_
#define CAMERA_FEATURES_AUTO_FRAMING_TESTS_AUTO_FRAMING_TEST_FIXTURE_H_

#include <map>
#include <memory>
#include <vector>

#include <base/test/task_environment.h>

#include "common/still_capture_processor.h"
#include "common/stream_manipulator.h"
#include "features/auto_framing/auto_framing_stream_manipulator.h"
#include "features/auto_framing/tests/test_image.h"

namespace cros::tests {

struct TestStreamConfig {
  base::TimeDelta duration;
  Rect<float> face_rect;
};

struct FramingResult {
  bool is_face_detected = false;
  bool is_crop_window_moving = false;
  bool is_crop_window_full = false;
};

class AutoFramingTestFixture {
 public:
  // Loads a test image that contains one face.  Test frames will be cropped
  // from the image to generate random face positions.
  bool LoadTestImage(const base::FilePath& path);

  // Sets up auto-framing pipeline that crops |full_{yuv,blob}_size| into
  // |client_{yuv,blob}_size|.  |test_stream_configs| describes the test video
  // content piecewisely.  |options|, |still_capture_processor| are used to
  // initialize AutoFramingStreamManipulator.
  bool SetUp(const Size& full_yuv_size,
             const Size& full_blob_size,
             const Size& client_yuv_size,
             const Size& client_blob_size,
             float frame_rate,
             std::vector<TestStreamConfig> test_stream_configs,
             const AutoFramingStreamManipulator::Options& options,
             std::unique_ptr<StillCaptureProcessor> still_capture_processor);

  // Runs one test frame on the pipeline.
  bool ProcessFrame(int64_t sensor_timestamp,
                    bool is_enabled,
                    bool has_yuv,
                    bool has_blob,
                    FramingResult* framing_result);

 private:
  ScopedBufferHandle CreateTestFrameWithFace(uint32_t width,
                                             uint32_t height,
                                             uint32_t format,
                                             uint32_t usage,
                                             const Rect<uint32_t>& face_rect);
  bool ProcessCaptureRequest(bool has_yuv,
                             bool has_blob,
                             std::vector<camera3_stream_t*>* requested_streams);
  bool ProcessCaptureResult(bool has_blob,
                            base::span<camera3_stream_t*> requested_streams,
                            int64_t sensor_timestamp,
                            FramingResult* framing_result);
  size_t GetFrameIndex(int64_t sensor_timestamp) const;

  base::test::SingleThreadTaskEnvironment task_environment_;

  std::optional<TestImage> test_image_one_face_;
  std::vector<TestStreamConfig> test_stream_configs_;

  StreamManipulator::RuntimeOptions runtime_options_;
  GpuResources gpu_resources_;
  Size active_array_size_;
  android::CameraMetadata static_info_;
  camera3_stream_t client_yuv_stream_ = {};
  camera3_stream_t client_blob_stream_ = {};
  std::vector<camera3_stream_t*> client_streams_;
  ScopedBufferHandle client_yuv_buffer_;
  ScopedBufferHandle client_blob_buffer_;
  std::map<const camera3_stream_t*, std::vector<ScopedBufferHandle>>
      modified_stream_buffers_;
  android::CameraMetadata result_metadata_;
  uint32_t frame_number_ = 0;
  std::optional<Rect<float>> last_crop_window_;
  std::unique_ptr<AutoFramingStreamManipulator>
      auto_framing_stream_manipulator_;
  base::WaitableEvent still_capture_result_received_;
};

}  // namespace cros::tests

#endif  // CAMERA_FEATURES_AUTO_FRAMING_TESTS_AUTO_FRAMING_TEST_FIXTURE_H_
