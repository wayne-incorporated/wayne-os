// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "camera3_test/camera3_still_capture_fixture.h"

#include <algorithm>
#include <iterator>

#include <camera/camera_metadata.h>

#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>

#include "cros-camera/common.h"

namespace camera3_test {

void Camera3StillCaptureFixture::SetUp() {
  ASSERT_EQ(0, cam_service_.Initialize(
                   base::BindRepeating(
                       &Camera3StillCaptureFixture::ProcessStillCaptureResult,
                       base::Unretained(this)),
                   Camera3Service::ProcessRecordingResultCallback()))
      << "Failed to initialize camera service";
  for (const auto& it : cam_ids_) {
    jpeg_max_sizes_[it] = cam_service_.GetStaticInfo(it)->GetJpegMaxSize();
  }
}

void Camera3StillCaptureFixture::ProcessStillCaptureResult(
    int cam_id,
    uint32_t frame_number,
    ScopedCameraMetadata metadata,
    cros::ScopedBufferHandle buffer) {
  StillCaptureResult* result = &still_capture_results_[cam_id];
  result->result_metadatas.emplace_back(std::move(metadata));
  result->buffer_handles.emplace_back(std::move(buffer));

  time_t cur_time;
  time(&cur_time);
  result->result_date_time.push_back(cur_time);
  sem_post(&result->capture_result_sem);
}

int Camera3StillCaptureFixture::WaitStillCaptureResult(
    int cam_id, const struct timespec& timeout) {
  // Wait for capture result callback
  return sem_timedwait(&still_capture_results_[cam_id].capture_result_sem,
                       &timeout);
}

Camera3StillCaptureFixture::StillCaptureResult::StillCaptureResult() {
  sem_init(&capture_result_sem, 0, 0);
}

Camera3StillCaptureFixture::StillCaptureResult::~StillCaptureResult() {
  sem_destroy(&capture_result_sem);
}

// Test parameters:
// - Camera ID
class Camera3SimpleStillCaptureTest
    : public Camera3StillCaptureFixture,
      public ::testing::WithParamInterface<int32_t> {
 public:
  Camera3SimpleStillCaptureTest()
      : Camera3StillCaptureFixture(std::vector<int>(1, GetParam())),
        cam_id_(GetParam()) {}

 protected:
  using ExifTestData = Camera3ExifValidator::ExifTestData;

  void TakePictureTest(uint32_t num_still_pictures,
                       bool require_3a_converged = true,
                       bool enable_zsl = false);

  int cam_id_;
};

TEST_P(Camera3SimpleStillCaptureTest, JpegExifTest) {
  // Reference:
  // camera2/cts/StillCaptureTest.java.java#testJpegExif
  ResolutionInfo jpeg_resolution =
      cam_service_.GetStaticInfo(cam_id_)
          ->GetSortedOutputResolutions(HAL_PIXEL_FORMAT_BLOB)
          .back();
  std::vector<ResolutionInfo> thumbnail_resolutions;
  EXPECT_TRUE(cam_service_.GetStaticInfo(cam_id_)->GetAvailableThumbnailSizes(
                  &thumbnail_resolutions) == 0 &&
              !thumbnail_resolutions.empty())
      << "JPEG thumbnail sizes are not available";
  // Size must contain (0, 0).
  EXPECT_TRUE(std::find(thumbnail_resolutions.begin(),
                        thumbnail_resolutions.end(),
                        ResolutionInfo(0, 0)) != thumbnail_resolutions.end())
      << "JPEG thumbnail sizes should contain (0, 0)";
  // Each size must be distinct.
  EXPECT_EQ(thumbnail_resolutions.size(),
            std::set<ResolutionInfo>(thumbnail_resolutions.begin(),
                                     thumbnail_resolutions.end())
                .size())
      << "JPEG thumbnail sizes contain duplicate items";
  // Must be sorted in ascending order by area, by width if areas are same.
  EXPECT_TRUE(std::is_sorted(thumbnail_resolutions.begin(),
                             thumbnail_resolutions.end()))
      << "JPEG thumbnail sizes are not in ascending order";

  ResolutionInfo preview_resolution =
      cam_service_.GetStaticInfo(cam_id_)
          ->GetSortedOutputResolutions(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED)
          .back();
  ResolutionInfo recording_resolution(0, 0);
  ASSERT_EQ(
      0, cam_service_.StartPreview(cam_id_, preview_resolution, jpeg_resolution,
                                   recording_resolution));

  ExifTestData exif_test_data[] = {
      {thumbnail_resolutions.front(), 90, 80, 75},
      {thumbnail_resolutions.front(), 180, 90, 85},
      {thumbnail_resolutions.back(), 270, 100, 100},
  };

  ScopedCameraMetadata metadata(
      clone_camera_metadata(cam_service_.ConstructDefaultRequestSettings(
          cam_id_, CAMERA3_TEMPLATE_STILL_CAPTURE)));
  ASSERT_NE(nullptr, metadata.get())
      << "Failed to create still capture metadata";
  for (const auto& it : exif_test_data) {
#define ARRAY_SIZE(A) (sizeof(A) / sizeof(*(A)))
    int32_t thumbnail_resolution[] = {it.thumbnail_resolution.Width(),
                                      it.thumbnail_resolution.Height()};
    EXPECT_EQ(0,
              UpdateMetadata(ANDROID_JPEG_THUMBNAIL_SIZE, thumbnail_resolution,
                             ARRAY_SIZE(thumbnail_resolution), &metadata));
    EXPECT_EQ(0, UpdateMetadata(ANDROID_JPEG_ORIENTATION, &it.orientation, 1,
                                &metadata));
    EXPECT_EQ(0, UpdateMetadata(ANDROID_JPEG_QUALITY, &it.jpeg_quality, 1,
                                &metadata));
    EXPECT_EQ(0, UpdateMetadata(ANDROID_JPEG_THUMBNAIL_QUALITY,
                                &it.thumbnail_quality, 1, &metadata));
    cam_service_.TakeStillCapture(cam_id_, metadata.get());
  }

  struct timespec timeout;
  clock_gettime(CLOCK_REALTIME, &timeout);
  timeout.tv_sec += ARRAY_SIZE(exif_test_data);  // 1 second per capture
  for (size_t i = 0; i < std::size(exif_test_data); i++) {
    ASSERT_EQ(0, WaitStillCaptureResult(cam_id_, timeout))
        << "Waiting for still capture result timeout";
  }

  Camera3ExifValidator exif_test(*cam_service_.GetStaticInfo(cam_id_));
  for (size_t i = 0;
       i < still_capture_results_[cam_id_].result_metadatas.size(); i++) {
    exif_test.ValidateExifKeys(
        jpeg_resolution, exif_test_data[i],
        still_capture_results_[cam_id_].buffer_handles[i],
        jpeg_max_sizes_[cam_id_],
        *still_capture_results_[cam_id_].result_metadatas[i].get(),
        still_capture_results_[cam_id_].result_date_time[i]);
  }
  cam_service_.StopPreview(cam_id_);
}

void Camera3SimpleStillCaptureTest::TakePictureTest(uint32_t num_still_pictures,
                                                    bool require_3a_converged,
                                                    bool enable_zsl) {
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

  // Trigger an auto focus run, and wait for AF locked.
  if (IsAFSupported()) {
    cam_service_.StartAutoFocus(cam_id_);
    int af_result = cam_service_.WaitForAutoFocusDone(cam_id_);
    if (require_3a_converged) {
      ASSERT_EQ(0, af_result) << "Wait for auto focus done timed out";
    } else if (af_result != 0) {
      LOGF(WARNING) << "Ignore AF converged timeout failure.";
    }
  }
  // Wait for AWB converged, then lock it.
  int awb_result = cam_service_.WaitForAWBConvergedAndLock(cam_id_);
  if (require_3a_converged) {
    ASSERT_EQ(0, awb_result) << "Wait for AWB converged timed out";
  } else if (awb_result != 0) {
    LOGF(WARNING) << "Ignore AWB converged timeout failure.";
  }
  // Trigger an AE precapture metering sequence and wait for AE converged.
  cam_service_.StartAEPrecapture(cam_id_);
  int ae_result = cam_service_.WaitForAEStable(cam_id_);
  if (require_3a_converged) {
    ASSERT_EQ(0, ae_result) << "Wait for AE stable timed out";
  } else if (ae_result != 0) {
    LOGF(WARNING) << "Ignore AE converged timeout failure.";
  }

  const camera_metadata_t* metadata =
      cam_service_.ConstructDefaultRequestSettings(
          cam_id_, CAMERA3_TEMPLATE_STILL_CAPTURE);
  if (enable_zsl) {
    android::CameraMetadata zsl_metadata(clone_camera_metadata(metadata));
    uint8_t enable_zsl = 1;
    ASSERT_EQ(zsl_metadata.update(ANDROID_CONTROL_ENABLE_ZSL, &enable_zsl, 1),
              0);
    auto* raw_zsl_metadata = zsl_metadata.getAndLock();
    for (uint32_t i = 0; i < num_still_pictures; i++) {
      cam_service_.TakeStillCapture(cam_id_, raw_zsl_metadata);

      // Take a brief pause to allow ZSL to accumulate raw buffers that can be
      // selected for private reprocessing.
      base::PlatformThread::Sleep(base::Milliseconds(500));
    }
    zsl_metadata.unlock(raw_zsl_metadata);
  } else {
    for (uint32_t i = 0; i < num_still_pictures; i++) {
      cam_service_.TakeStillCapture(cam_id_, metadata);
    }
  }

  cam_service_.StopPreview(cam_id_);
}

TEST_P(Camera3SimpleStillCaptureTest, TakePictureTest) {
  TakePictureTest(1);
}

TEST_P(Camera3SimpleStillCaptureTest, PerformanceTest) {
  TakePictureTest(2);
}

TEST_P(Camera3SimpleStillCaptureTest, TakePictureZslTest) {
  if (!cam_service_.GetStaticInfo(cam_id_)->HasAvailableRequestKey(
          ANDROID_CONTROL_ENABLE_ZSL)) {
    GTEST_SKIP();
  }
  TakePictureTest(10, /*require_3a_converged=*/true, /*enable_zsl=*/true);
}

// Test parameters:
// - Camera ID
class Camera3DumpSimpleStillCaptureTest : public Camera3SimpleStillCaptureTest {
 public:
  Camera3DumpSimpleStillCaptureTest() : dump_path_(GetCommandLineDumpPath()) {}

  void ProcessStillCaptureResult(int cam_id,
                                 uint32_t frame_number,
                                 ScopedCameraMetadata metadata,
                                 cros::ScopedBufferHandle buffer) override;

 protected:
  base::FilePath dump_path_;

  inline base::FilePath GetCommandLineDumpPath() {
    return base::CommandLine::ForCurrentProcess()->GetSwitchValuePath(
        "dump_still_capture_path");
  }
};

void Camera3DumpSimpleStillCaptureTest::ProcessStillCaptureResult(
    int cam_id,
    uint32_t frame_number,
    ScopedCameraMetadata metadata,
    cros::ScopedBufferHandle buffer) {
  size_t jpeg_max_size = jpeg_max_sizes_[cam_id_];
  void* buf_addr = nullptr;
  ASSERT_EQ(0, Camera3TestGralloc::GetInstance()->Lock(
                   *buffer, 0, 0, 0, jpeg_max_size, 1, &buf_addr));
  ASSERT_NE(nullptr, buf_addr);

  {
    // Ensure buffer unlock process is executed when exiting from ASSERT_XX.
    struct UnlockBuf {
      void operator()(buffer_handle_t* handle) {
        Camera3TestGralloc::GetInstance()->Unlock(*handle);
      }
    };
    std::unique_ptr<buffer_handle_t, UnlockBuf> unlock(buffer.get());

    auto jpeg_blob = reinterpret_cast<camera3_jpeg_blob_t*>(
        static_cast<uint8_t*>(buf_addr) + jpeg_max_size -
        sizeof(camera3_jpeg_blob_t));
    ASSERT_LE(buf_addr, static_cast<void*>(jpeg_blob));
    ASSERT_EQ(CAMERA3_JPEG_BLOB_ID, jpeg_blob->jpeg_blob_id);

    auto jpeg_size = jpeg_blob->jpeg_size;
    ASSERT_EQ(jpeg_size,
              base::WriteFile(dump_path_, static_cast<const char*>(buf_addr),
                              jpeg_size));
  }
}

TEST_P(Camera3DumpSimpleStillCaptureTest, DumpCaptureResult) {
  // Run only if --dump_still_capture_path argument presented.
  if (dump_path_.empty()) {
    GTEST_SKIP();
  }
  TakePictureTest(1, /*require_3a_converged=*/false);
}

// Test parameters:
// - Camera ID, preview resolution, JPEG resolution
class Camera3JpegResolutionTest
    : public Camera3StillCaptureFixture,
      public ::testing::WithParamInterface<
          std::tuple<int32_t, ResolutionInfo, ResolutionInfo>> {
 public:
  Camera3JpegResolutionTest()
      : Camera3StillCaptureFixture(
            std::vector<int>(1, std::get<0>(GetParam()))),
        cam_id_(std::get<0>(GetParam())) {}

 protected:
  int cam_id_;
};

TEST_P(Camera3JpegResolutionTest, JpegResolutionTest) {
  ResolutionInfo preview_resolution(std::get<1>(GetParam()));
  ResolutionInfo jpeg_resolution(std::get<2>(GetParam()));
  VLOGF(1) << "Device " << cam_id_;
  VLOGF(1) << "Preview resolution " << preview_resolution.Width() << "x"
           << preview_resolution.Height();
  VLOGF(1) << "JPEG resolution " << jpeg_resolution.Width() << "x"
           << jpeg_resolution.Height();

  ResolutionInfo recording_resolution(0, 0);
  ASSERT_EQ(
      0, cam_service_.StartPreview(cam_id_, preview_resolution, jpeg_resolution,
                                   recording_resolution));
  ScopedCameraMetadata metadata(
      clone_camera_metadata(cam_service_.ConstructDefaultRequestSettings(
          cam_id_, CAMERA3_TEMPLATE_STILL_CAPTURE)));
  ASSERT_NE(nullptr, metadata.get())
      << "Failed to create still capture metadata";
  cam_service_.TakeStillCapture(cam_id_, metadata.get());
  cam_service_.StopPreview(cam_id_);

  ASSERT_EQ(1, still_capture_results_[cam_id_].buffer_handles.size())
      << "Incorrect number of still captures received";
  JpegExifInfo jpeg_exif_info(still_capture_results_[cam_id_].buffer_handles[0],
                              jpeg_max_sizes_[cam_id_]);
  ASSERT_TRUE(jpeg_exif_info.Initialize());
  EXPECT_EQ(jpeg_resolution, jpeg_exif_info.jpeg_resolution)
      << "JPEG size result and request should match";
}

INSTANTIATE_TEST_SUITE_P(
    Camera3StillCaptureTest,
    Camera3SimpleStillCaptureTest,
    ::testing::ValuesIn(Camera3Module().GetTestCameraIds()));

static std::vector<std::tuple<int, ResolutionInfo, ResolutionInfo>>
IterateCameraIdPreviewJpegResolution() {
  std::vector<std::tuple<int, ResolutionInfo, ResolutionInfo>> result;
  auto cam_ids = Camera3Module().GetTestCameraIds();
  for (const auto& cam_id : cam_ids) {
    auto preview_resolutions = Camera3Module().GetSortedOutputResolutions(
        cam_id, HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED);
    auto jpeg_resolutions = Camera3Module().GetSortedOutputResolutions(
        cam_id, HAL_PIXEL_FORMAT_BLOB);
    for (const auto& preview_resolution : preview_resolutions) {
      for (const auto& jpeg_resolution : jpeg_resolutions) {
        result.emplace_back(cam_id, preview_resolution, jpeg_resolution);
      }
    }
  }
  return result;
}

INSTANTIATE_TEST_SUITE_P(
    Camera3StillCaptureTest,
    Camera3JpegResolutionTest,
    ::testing::ValuesIn(IterateCameraIdPreviewJpegResolution()));

INSTANTIATE_TEST_SUITE_P(
    Camera3StillCaptureTest,
    Camera3DumpSimpleStillCaptureTest,
    ::testing::ValuesIn(Camera3Module().GetTestCameraIds()));

}  // namespace camera3_test
