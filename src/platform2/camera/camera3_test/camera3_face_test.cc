// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "camera3_test/camera3_preview_fixture.h"
#include "camera3_test/camera3_still_capture_fixture.h"

#include <unistd.h>

#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/strings/string_number_conversions.h>
#include <libyuv.h>

namespace camera3_test {

// Test parameters:
// - Camera ID
class Camera3FaceDetectionTest : public Camera3PreviewFixture,
                                 public ::testing::WithParamInterface<int32_t> {
 public:
  const uint32_t kNumPreviewFrames = 20;
  const uint32_t kTimeoutMsPerFrame = 1000;
  Camera3FaceDetectionTest()
      : Camera3PreviewFixture(std::vector<int>(1, GetParam())),
        cam_id_(GetParam()),
        expected_num_faces_(GetCommandLineFaceDetectNumber()) {}

 protected:
  void SetUp() override;

  void ProcessPreviewResult(int cam_id,
                            uint32_t frame_number,
                            ScopedCameraMetadata metadata);

  int GetCommandLineFaceDetectNumber() {
    std::string switch_value =
        base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
            "expected_num_faces");
    if (switch_value == "") {
      return -1;
    }
    int value;
    if (!base::StringToInt(switch_value, &value)) {
      LOG(ERROR) << "Failed to convert " << switch_value << " to int";
      return -1;
    }
    if (value < 0) {
      return -1;
    }
    return value;
  }

  void CheckNumOfFaces(int num_faces);

  int cam_id_;
  int expected_num_faces_;

 private:
  ScopedCameraMetadata result_metadata_;
};

void Camera3FaceDetectionTest::SetUp() {
  ASSERT_EQ(0, cam_service_.Initialize(
                   Camera3Service::ProcessStillCaptureResultCallback(),
                   Camera3Service::ProcessRecordingResultCallback(),
                   base::BindRepeating(
                       &Camera3FaceDetectionTest::ProcessPreviewResult,
                       base::Unretained(this))))
      << "Failed to initialize camera service";
}

void Camera3FaceDetectionTest::ProcessPreviewResult(
    int cam_id, uint32_t /*frame_number*/, ScopedCameraMetadata metadata) {
  result_metadata_ = std::move(metadata);
}

void Camera3FaceDetectionTest::CheckNumOfFaces(int num_faces) {
  ASSERT_NE(nullptr, result_metadata_.get())
      << "Result metadata is unavailable";
  camera_metadata_ro_entry_t entry;
  int result = find_camera_metadata_ro_entry(
      result_metadata_.get(), ANDROID_STATISTICS_FACE_RECTANGLES, &entry);
  // Accept no rectangles.
  if (num_faces == 0 && result != 0) {
    return;
  }
  ASSERT_EQ(0, result)
      << "Metadata key ANDROID_STATISTICS_FACE_RECTANGLES not found";
  EXPECT_EQ(num_faces * 4, entry.count)
      << "Expect face rectangles size " << num_faces * 4 << " but detected "
      << entry.count;
  ASSERT_EQ(
      0, find_camera_metadata_ro_entry(result_metadata_.get(),
                                       ANDROID_STATISTICS_FACE_SCORES, &entry))
      << "Metadata key ANDROID_STATISTICS_FACE_SCORES not found";
  EXPECT_EQ(num_faces, entry.count)
      << "Expect " << num_faces << " faces, but detected " << entry.count
      << " faces";
  result_metadata_.reset();
}

TEST_P(Camera3FaceDetectionTest, Detection) {
  // Run only if --expected_num_faces argument presented.
  if (expected_num_faces_ < 0) {
    GTEST_SKIP();
  }

  auto IsAFSupported = [this]() {
    std::vector<uint8_t> available_af_modes;
    cam_service_.GetStaticInfo(cam_id_)->GetAvailableAFModes(
        &available_af_modes);
    uint8_t af_modes[] = {ANDROID_CONTROL_AF_MODE_AUTO,
                          ANDROID_CONTROL_AF_MODE_CONTINUOUS_PICTURE,
                          ANDROID_CONTROL_AF_MODE_CONTINUOUS_VIDEO,
                          ANDROID_CONTROL_AF_MODE_MACRO};
    for (const auto& it : af_modes) {
      if (std::find(available_af_modes.begin(), available_af_modes.end(), it) !=
          available_af_modes.end()) {
        return true;
      }
    }
    return false;
  };

  ASSERT_TRUE(cam_service_.GetStaticInfo(cam_id_)->IsKeyAvailable(
      ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES))
      << "NO ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES key in static "
         "info";
  std::set<uint8_t> face_detect_modes;
  ASSERT_EQ(0, cam_service_.GetStaticInfo(cam_id_)->GetAvailableFaceDetectModes(
                   &face_detect_modes) != 0)
      << "Failed to get face detect modes";
  ASSERT_NE(face_detect_modes.find(ANDROID_STATISTICS_FACE_DETECT_MODE_SIMPLE),
            face_detect_modes.end())
      << "Can't find ANDROID_STATISTICS_FACE_DETECT_MODE_SIMPLE";

  auto resolution =
      cam_service_.GetStaticInfo(cam_id_)
          ->GetSortedOutputResolutions(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED)
          .back();
  ResolutionInfo jpeg_resolution(0, 0), recording_resolution(0, 0);
  ASSERT_EQ(0, cam_service_.StartPreview(cam_id_, resolution, jpeg_resolution,
                                         recording_resolution))
      << "Starting preview fails";

  // Trigger an auto focus run, and wait for AF locked.
  if (IsAFSupported()) {
    cam_service_.StartAutoFocus(cam_id_);
    ASSERT_EQ(0, cam_service_.WaitForAutoFocusDone(cam_id_))
        << "Wait for auto focus done timed out";
  }
  // Wait for AWB converged, then lock it.
  ASSERT_EQ(0, cam_service_.WaitForAWBConvergedAndLock(cam_id_))
      << "Wait for AWB converged timed out";

  // Trigger an AE precapture metering sequence and wait for AE converged.
  cam_service_.StartAEPrecapture(cam_id_);
  ASSERT_EQ(0, cam_service_.WaitForAEStable(cam_id_))
      << "Wait for AE stable timed out";

  // Check there is no face detected before enabling face detection
  ASSERT_EQ(0, cam_service_.WaitForPreviewFrames(cam_id_, kNumPreviewFrames,
                                                 kTimeoutMsPerFrame));
  CheckNumOfFaces(0);

  cam_service_.StartFaceDetection(cam_id_);
  ASSERT_EQ(0, cam_service_.WaitForPreviewFrames(cam_id_, kNumPreviewFrames,
                                                 kTimeoutMsPerFrame));
  CheckNumOfFaces(expected_num_faces_);

  // Check no face detected after stop face detection
  cam_service_.StopFaceDetection(cam_id_);
  ASSERT_EQ(0, cam_service_.WaitForPreviewFrames(cam_id_, kNumPreviewFrames,
                                                 kTimeoutMsPerFrame));
  CheckNumOfFaces(0);

  cam_service_.StopPreview(cam_id_);
}

INSTANTIATE_TEST_SUITE_P(
    Camera3FaceTest,
    Camera3FaceDetectionTest,
    ::testing::ValuesIn(Camera3Module().GetTestCameraIds()));

// Test parameters:
// - Camera ID
class Camera3FaceAutoExposureTest
    : public Camera3StillCaptureFixture,
      public ::testing::WithParamInterface<int32_t> {
 public:
  // we require face auto exposure works in 90 frames.
  const uint32_t kNumPreviewFrames = 90;
  const uint32_t kTimeoutMsPerFrame = 1000;

  Camera3FaceAutoExposureTest()
      : Camera3StillCaptureFixture(std::vector<int>(1, GetParam())),
        cam_id_(GetParam()),
        expected_num_faces_(GetCommandLineFaceDetectNumber()),
        dump_path_(GetCommandLineDumpPath()) {}

 protected:
  void SetUp() override;
  void TearDown() override;

  void ProcessPreviewResult(int cam_id,
                            uint32_t frame_number,
                            ScopedCameraMetadata metadata);

  struct ImageI420 {
    ImageI420(uint32_t w, uint32_t h);
    int SaveToFile(base::FilePath file_path) const;

    uint32_t width;
    uint32_t height;
    std::vector<uint8_t> data;
    uint32_t size;

    uint8_t* y_addr;
    uint8_t* u_addr;
    uint8_t* v_addr;

    uint32_t y_stride;
    uint32_t u_stride;
    uint32_t v_stride;
  };
  using ScopedImageI420 = std::unique_ptr<ImageI420>;

  ScopedImageI420 ConvertJpegToI420(const cros::ScopedBufferHandle& buffer,
                                    int width,
                                    int height);

  // Get the Luma of the face. |enable_face_ae| indicates that we get the Luma
  // value from face auto exposure or not. If there are many faces detected,
  // only gets the luma value of the first face reported from camera hal.
  void GetFaceLumaValue(bool enable_face_ae);
  void Do3AConverged();

  inline base::FilePath GetCommandLineDumpPath() {
    return base::CommandLine::ForCurrentProcess()->GetSwitchValuePath(
        "dump_path");
  }

  int GetCommandLineFaceDetectNumber() {
    std::string switch_value =
        base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
            "expected_num_faces");
    if (switch_value == "") {
      return -1;
    }
    int value;
    if (!base::StringToInt(switch_value, &value)) {
      LOG(ERROR) << "Failed to convert " << switch_value << " to int";
      return -1;
    }
    if (value < 0) {
      return -1;
    }
    return value;
  }

  int cam_id_;
  int expected_num_faces_;
  base::FilePath dump_path_;

 private:
  ScopedCameraMetadata preview_result_metadata_;
};

void Camera3FaceAutoExposureTest::SetUp() {
  ASSERT_EQ(0, cam_service_.Initialize(
                   base::BindRepeating(
                       &Camera3StillCaptureFixture::ProcessStillCaptureResult,
                       base::Unretained(this)),
                   Camera3Service::ProcessRecordingResultCallback(),
                   base::BindRepeating(
                       &Camera3FaceAutoExposureTest::ProcessPreviewResult,
                       base::Unretained(this))))
      << "Failed to initialize camera service";
}

void Camera3FaceAutoExposureTest::TearDown() {
  cam_service_.Destroy();
}

void Camera3FaceAutoExposureTest::ProcessPreviewResult(
    int cam_id, uint32_t /*frame_number*/, ScopedCameraMetadata metadata) {
  preview_result_metadata_ = std::move(metadata);
}

#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
Camera3FaceAutoExposureTest::ImageI420::ImageI420(uint32_t w, uint32_t h)
    : width(w), height(h) {
  y_stride = DIV_ROUND_UP(w, 2) * 2;
  u_stride = DIV_ROUND_UP(w, 2);
  v_stride = DIV_ROUND_UP(w, 2);
  size_t y_plane_size = y_stride * height;
  size = y_plane_size * 3 / 2;
  data.resize(size);
  y_addr = data.data();
  u_addr = y_addr + y_plane_size;
  v_addr = u_addr + y_plane_size / 4;
}

int Camera3FaceAutoExposureTest::ImageI420::SaveToFile(
    base::FilePath file_path) const {
  if (base::WriteFile(file_path, reinterpret_cast<const char*>(data.data()),
                      size) != size) {
    LOGF(ERROR) << "Failed to write file " << file_path;
    return -EINVAL;
  }
  return 0;
}

Camera3FaceAutoExposureTest::ScopedImageI420
Camera3FaceAutoExposureTest::ConvertJpegToI420(
    const cros::ScopedBufferHandle& buffer, int width, int height) {
  auto gralloc = Camera3TestGralloc::GetInstance();
  buffer_handle_t handle = *buffer;
  if (gralloc->GetFormat(handle) != HAL_PIXEL_FORMAT_BLOB) {
    LOGF(ERROR) << "Invalid format";
    return ScopedImageI420(nullptr);
  }
  size_t jpeg_max_size = cam_service_.GetStaticInfo(cam_id_)->GetJpegMaxSize();
  void* buf_addr = nullptr;
  if (gralloc->Lock(handle, 0, 0, 0, jpeg_max_size, 1, &buf_addr)) {
    LOGF(ERROR) << "Failed to lock buffer";
    return ScopedImageI420(nullptr);
  }
  auto jpeg_blob = reinterpret_cast<camera3_jpeg_blob_t*>(
      static_cast<uint8_t*>(buf_addr) + jpeg_max_size -
      sizeof(camera3_jpeg_blob_t));
  if (static_cast<void*>(jpeg_blob) < buf_addr ||
      jpeg_blob->jpeg_blob_id != CAMERA3_JPEG_BLOB_ID) {
    gralloc->Unlock(handle);
    LOGF(ERROR) << "Invalid JPEG BLOB ID";
    return ScopedImageI420(nullptr);
  }

  ScopedImageI420 i420(new ImageI420(width, height));
  if (libyuv::MJPGToI420(static_cast<uint8_t*>(buf_addr), jpeg_blob->jpeg_size,
                         i420->y_addr, i420->y_stride, i420->u_addr,
                         i420->u_stride, i420->v_addr, i420->v_stride, width,
                         height, width, height) != 0) {
    LOGF(ERROR) << "Failed to convert image from JPEG";
    gralloc->Unlock(handle);
    return ScopedImageI420(nullptr);
  }
  gralloc->Unlock(handle);

  return i420;
}

void Camera3FaceAutoExposureTest::Do3AConverged() {
  auto IsAFSupported = [this]() {
    std::vector<uint8_t> available_af_modes;
    cam_service_.GetStaticInfo(cam_id_)->GetAvailableAFModes(
        &available_af_modes);
    uint8_t af_modes[] = {ANDROID_CONTROL_AF_MODE_AUTO,
                          ANDROID_CONTROL_AF_MODE_CONTINUOUS_PICTURE,
                          ANDROID_CONTROL_AF_MODE_CONTINUOUS_VIDEO,
                          ANDROID_CONTROL_AF_MODE_MACRO};
    for (const auto& it : af_modes) {
      if (std::find(available_af_modes.begin(), available_af_modes.end(), it) !=
          available_af_modes.end()) {
        return true;
      }
    }
    return false;
  };

  // Trigger an auto focus run, and wait for AF locked.
  if (IsAFSupported()) {
    cam_service_.StartAutoFocus(cam_id_);
    int af_result = cam_service_.WaitForAutoFocusDone(cam_id_);
    if (af_result != 0) {
      LOGF(WARNING) << "Ignore AF converged timeout failure.";
    }
  }
  // Wait for AWB converged, then lock it.
  int awb_result = cam_service_.WaitForAWBConvergedAndLock(cam_id_);
  if (awb_result != 0) {
    LOGF(WARNING) << "Ignore AWB converged timeout failure.";
  }
  // Trigger an AE precapture metering sequence and wait for AE converged.
  cam_service_.StartAEPrecapture(cam_id_);
  int ae_result = cam_service_.WaitForAEStable(cam_id_);
  if (ae_result != 0) {
    LOGF(WARNING) << "Ignore AE converged timeout failure.";
  }
}

void Camera3FaceAutoExposureTest::GetFaceLumaValue(bool enable_face_ae) {
  ASSERT_TRUE(cam_service_.GetStaticInfo(cam_id_)->IsKeyAvailable(
      ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES))
      << "NO ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES key in static "
         "info";
  std::set<uint8_t> face_detect_modes;
  ASSERT_EQ(0, cam_service_.GetStaticInfo(cam_id_)->GetAvailableFaceDetectModes(
                   &face_detect_modes) != 0)
      << "Failed to get face detect modes";
  ASSERT_NE(face_detect_modes.find(ANDROID_STATISTICS_FACE_DETECT_MODE_SIMPLE),
            face_detect_modes.end())
      << "Can't find ANDROID_STATISTICS_FACE_DETECT_MODE_SIMPLE";

  // Get the max resolution.
  ResolutionInfo jpeg_resolution =
      cam_service_.GetStaticInfo(cam_id_)
          ->GetSortedOutputResolutions(HAL_PIXEL_FORMAT_BLOB)
          .back();
  ResolutionInfo preview_resolution =
      cam_service_.GetStaticInfo(cam_id_)
          ->GetSortedOutputResolutions(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED)
          .back();
  ResolutionInfo recording_resolution(0, 0);
  ASSERT_EQ(
      0, cam_service_.StartPreview(cam_id_, preview_resolution, jpeg_resolution,
                                   recording_resolution));

  Do3AConverged();

  // Get face region
  cam_service_.StartFaceDetection(cam_id_);
  ASSERT_EQ(0, cam_service_.WaitForPreviewFrames(cam_id_, kNumPreviewFrames,
                                                 kTimeoutMsPerFrame));
  ASSERT_NE(nullptr, preview_result_metadata_.get())
      << "Result metadata is unavailable";
  camera_metadata_ro_entry_t entry;
  int result =
      find_camera_metadata_ro_entry(preview_result_metadata_.get(),
                                    ANDROID_STATISTICS_FACE_RECTANGLES, &entry);
  ASSERT_EQ(0, result)
      << "Metadata key ANDROID_STATISTICS_FACE_RECTANGLES not found";
  if (expected_num_faces_ * 4 != entry.count) {
    if (!dump_path_.empty()) {
      // dump image for debugging
      const camera_metadata_t* metadata =
          cam_service_.ConstructDefaultRequestSettings(
              cam_id_, CAMERA3_TEMPLATE_STILL_CAPTURE);
      cam_service_.TakeStillCapture(cam_id_, metadata);

      struct timespec timeout;
      clock_gettime(CLOCK_REALTIME, &timeout);
      timeout.tv_sec += 1;
      ASSERT_EQ(0, WaitStillCaptureResult(cam_id_, timeout))
          << "Waiting for still capture result timeout";

      ScopedImageI420 image =
          ConvertJpegToI420(still_capture_results_[cam_id_].buffer_handles[0],
                            jpeg_resolution.Width(), jpeg_resolution.Height());
      if (image != nullptr) {
        image->SaveToFile(dump_path_);
      }
    }
    ASSERT_TRUE(false) << "Expect face rectangles size "
                       << expected_num_faces_ * 4 << " but detected "
                       << entry.count;
  }

  int32_t x1 = entry.data.i32[0];
  int32_t y1 = entry.data.i32[1];
  int32_t x2 = entry.data.i32[2];
  int32_t y2 = entry.data.i32[3];
  LOGF(INFO) << "Face rectangle(x1, y1, x2, y2):" << x1 << " " << y1 << " "
             << x2 << " " << y2;

  preview_result_metadata_.reset();

  if (!enable_face_ae) {
    cam_service_.StopFaceDetection(cam_id_);
    ASSERT_EQ(0, cam_service_.WaitForPreviewFrames(cam_id_, kNumPreviewFrames,
                                                   kTimeoutMsPerFrame));
  }

  const camera_metadata_t* metadata =
      cam_service_.ConstructDefaultRequestSettings(
          cam_id_, CAMERA3_TEMPLATE_STILL_CAPTURE);
  cam_service_.TakeStillCapture(cam_id_, metadata);

  struct timespec timeout;
  clock_gettime(CLOCK_REALTIME, &timeout);
  timeout.tv_sec += 1;
  ASSERT_EQ(0, WaitStillCaptureResult(cam_id_, timeout))
      << "Waiting for still capture result timeout";
  cam_service_.StopPreview(cam_id_);

  ScopedImageI420 image =
      ConvertJpegToI420(still_capture_results_[cam_id_].buffer_handles[0],
                        jpeg_resolution.Width(), jpeg_resolution.Height());
  ASSERT_NE(image, nullptr);
  // Calculate average Y value.
  int32_t total_y = 0;
  int32_t total_points = 0;
  for (size_t y = y1; y <= y2; ++y) {
    for (size_t x = x1; x <= x2; ++x) {
      total_y += image->y_addr[y * image->y_stride + x];
      ++total_points;
      // Draw rectangle for debugging
      if (y == y1 || y == y2 || x == x1 || x == x2) {
        image->y_addr[y * image->y_stride + x] = 0;
      }
    }
  }
  if (!dump_path_.empty()) {
    image->SaveToFile(dump_path_);
  }
  LOGF(INFO) << "Luma Value:" << total_y / total_points;
}

TEST_P(Camera3FaceAutoExposureTest, GetFaceLumaValueWithFaceAutoExposure) {
  // Run only if --expected_num_faces argument presented.
  if (expected_num_faces_ < 0) {
    GTEST_SKIP();
  }
  GetFaceLumaValue(true);
}

TEST_P(Camera3FaceAutoExposureTest, GetFaceLumaValueWithoutFaceAutoExposure) {
  // Run only if --expected_num_faces argument presented.
  if (expected_num_faces_ < 0) {
    GTEST_SKIP();
  }
  GetFaceLumaValue(false);
}

INSTANTIATE_TEST_SUITE_P(
    Camera3FaceTest,
    Camera3FaceAutoExposureTest,
    ::testing::ValuesIn(Camera3Module().GetTestCameraIds()));

}  // namespace camera3_test
