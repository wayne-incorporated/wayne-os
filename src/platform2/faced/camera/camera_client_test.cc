// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/camera/camera_client.h"

#include <memory>
#include <string>

#include <base/task/thread_pool.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <linux/videodev2.h>

#include "faced/camera/fake_camera_service.h"
#include "faced/camera/test_utils.h"
#include "faced/testing/status.h"
#include "faced/util/blocking_future.h"
#include "faced/util/task.h"

namespace faced {
namespace {

using ::testing::IsEmpty;

// CameraClient tests require a task environment present.
class CameraClientTest : public ::testing::Test {
 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

// Tests conversions of common fourcc codes
TEST(FourccToStringTest, FourccToString) {
  EXPECT_EQ(FourccToString(V4L2_PIX_FMT_NV12), "NV12");
  EXPECT_EQ(FourccToString(V4L2_PIX_FMT_MJPEG), "MJPG");

  // Codes with unprintable characters are just printed as hex.
  EXPECT_EQ(FourccToString(0x00112233), "0x00112233");
}

// Tests IsFormatEqual for identical and different formats
TEST(IsFormatEqualTest, IsFormatEqual) {
  EXPECT_TRUE(
      IsFormatEqual(testing::kYuvHighDefCamera, testing::kYuvHighDefCamera));
  EXPECT_FALSE(
      IsFormatEqual(testing::kYuvHighDefCamera, testing::kYuvStdDefCamera));
}

// Tests CrosCameraClient::Create()
//
// Tests that the camera client is able to probe info for a single fake camera
// info.
TEST_F(CameraClientTest, Create) {
  auto fake_camera_service_connector =
      std::make_unique<testing::FakeCameraService>();
  testing::CameraSet yuv_camera_set = testing::YuvCameraSet();
  fake_camera_service_connector->AddCameraInfo(yuv_camera_set.camera_info,
                                               /*is_removed=*/false);

  // Create a camera client.
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<CameraClient> camera_client,
      CrosCameraClient::Create(std::move(fake_camera_service_connector)));

  // Check that the expected formats are reported.
  FACE_ASSERT_OK_AND_ASSIGN(std::vector<CameraClient::DeviceInfo> devices,
                            camera_client->GetDevices());
  ASSERT_EQ(devices.size(), 1);
  EXPECT_EQ(devices[0].id, 0);
  EXPECT_EQ(devices[0].name, "TestYuvCamera");
  ASSERT_EQ(devices[0].formats.size(), 2);
  EXPECT_TRUE(IsFormatEqual(devices[0].formats[0],
                            testing::YuvCameraSet().format_infos[0]));
  EXPECT_TRUE(IsFormatEqual(devices[0].formats[1],
                            testing::YuvCameraSet().format_infos[1]));
}

// Simple subclass of FrameProcessor that processes a certain number of
// frames then stops.
class SimpleFrameProcessor : public FrameProcessor {
 public:
  explicit SimpleFrameProcessor(int num_frames_to_process)
      : num_frames_to_process_(num_frames_to_process) {}

  // Increments the frame counter and calls processing_complete_ when the
  // requested number of frames have been processed.
  void ProcessFrame(std::unique_ptr<Frame> frame,
                    ProcessFrameDoneCallback done) override {
    num_frames_processed_++;

    if (num_frames_processed_ == num_frames_to_process_) {
      PostToCurrentSequence(base::BindOnce(std::move(done), absl::OkStatus()));
      return;
    }

    PostToCurrentSequence(base::BindOnce(std::move(done), std::nullopt));
  }

  // Returns how many frames have been processed.
  int FramesProcessed() { return num_frames_processed_; }

 private:
  int num_frames_processed_ = 0;
  int num_frames_to_process_ = 0;
};

// Tests CameraClient::CaptureFrames() with a custom FrameProcessor
TEST_F(CameraClientTest, CaptureFrames) {
  // Create a fake camera service.
  auto fake_camera_service_connector =
      std::make_unique<testing::FakeCameraService>();
  testing::CameraSet yuv_camera_set = testing::YuvCameraSet();
  fake_camera_service_connector->AddCameraInfo(yuv_camera_set.camera_info,
                                               /*is_removed=*/false);

  // Add frames available from the fake camera
  const int kFramesAvailable = 10;
  const int kFramesToProcess = 5;
  for (int i = 0; i < kFramesAvailable; i++) {
    fake_camera_service_connector->AddResult(yuv_camera_set.result);
  }

  // Create a camera client.
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<CameraClient> camera_client,
      CrosCameraClient::Create(std::move(fake_camera_service_connector)));

  // Start a capture.
  BlockingFuture<absl::Status> status;
  auto frame_processor =
      base::MakeRefCounted<SimpleFrameProcessor>(kFramesToProcess);
  camera_client->CaptureFrames(
      {.camera_id = 0, .format = yuv_camera_set.format_infos[0]},
      frame_processor, status.PromiseCallback());

  // Wait for the capture to finish, and ensure we received the
  // expected number of frames.
  EXPECT_TRUE(status.Wait().ok());
  ASSERT_EQ(frame_processor->FramesProcessed(), kFramesToProcess);
}

TEST(GetHighestResolutionFormat, EmptyDevice) {
  EXPECT_EQ(GetHighestResolutionFormat(CameraClient::DeviceInfo{}),
            std::nullopt);
}

cros_cam_format_info_t MakeFormat(uint32_t fourcc, int width, int height) {
  return cros_cam_format_info_t{
      .fourcc = fourcc,
      .width = width,
      .height = height,
  };
}

TEST(GetHighestResolutionFormat, LargestResolutionChosen) {
  // Create a device with three resolutions.
  std::optional<CameraClient::CaptureFramesConfig> config =
      GetHighestResolutionFormat(CameraClient::DeviceInfo{
          .id = 42,
          .formats =
              {
                  MakeFormat(/*fourcc=*/100, 1, 1),
                  MakeFormat(/*fourcc=*/101, 3, 3),  // max resolution
                  MakeFormat(/*fourcc=*/102, 2, 2),
              },
      });

  // Ensure the largest resolution was found.
  ASSERT_TRUE(config.has_value());
  EXPECT_EQ(config->camera_id, 42);
  EXPECT_EQ(config->format.fourcc, 101);
  EXPECT_EQ(config->format.height, 3);
  EXPECT_EQ(config->format.width, 3);
}

TEST(GetHighestResolutionFormat, PredicateRespected) {
  // Create a device with three resolutions.
  CameraClient::DeviceInfo device{
      .id = 42,
      .formats =
          {
              MakeFormat(/*fourcc=*/100, 1, 1),
              MakeFormat(/*fourcc=*/101, 3, 3),
              MakeFormat(/*fourcc=*/102, 2, 2),
          },
  };

  // Get the maximum resolution that is not 3x3.
  std::optional<CameraClient::CaptureFramesConfig> config =
      GetHighestResolutionFormat(
          device,
          [](const cros_cam_format_info_t& info) { return info.width != 3; });

  // Ensure we found the 2x2 format.
  ASSERT_TRUE(config.has_value());
  EXPECT_EQ(config->camera_id, 42);
  EXPECT_EQ(config->format.fourcc, 102);
  EXPECT_EQ(config->format.height, 2);
  EXPECT_EQ(config->format.width, 2);
}

}  // namespace
}  // namespace faced
