/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <cstdlib>
#include <set>
#include <vector>

#include <base/check_op.h>
#include <base/command_line.h>
#include <base/containers/cxx20_erase.h>
#include <base/files/file_util.h>
#include <base/process/launch.h>
#include <base/posix/safe_strerror.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/synchronization/waitable_event.h>
#include <base/time/time.h>
#include <base/threading/thread.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <gtest/gtest.h>
#include <libyuv.h>
#include <linux/videodev2.h>

#include "common/libcamera_connector_test/i420_buffer.h"
#include "common/libcamera_connector_test/util.h"
#include "cros-camera/camera_service_connector.h"
#include "cros-camera/common.h"
#include "cros-camera/common_types.h"
#include "cros-camera/future.h"
#include "cros-camera/ipc_util.h"

namespace cros::tests {

struct ContinuousCaptureOptions {
  int capture_duration_secs = 3;
  int camera_id = 0;
  Size capture_size{1280, 720};
  int fps = 30;
  uint32_t format = V4L2_PIX_FMT_NV12;
} g_cont_capture_args;

cros::Size ParseSize(std::string size_str) {
  CHECK(!size_str.empty());
  std::vector<std::string> arg_split = base::SplitString(
      size_str, "x", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  CHECK_EQ(arg_split.size(), 2);
  Size ret;
  CHECK(base::StringToUint(arg_split[0], &ret.width));
  CHECK(base::StringToUint(arg_split[1], &ret.height));
  return ret;
}

uint32_t ParseFormat(std::string argv) {
  CHECK(!argv.empty());
  std::string upper_argv = base::ToUpperASCII(argv);

  CHECK(upper_argv == "NV12" || upper_argv == "MJPEG")
      << "Unrecognized input format: " << argv;
  if (upper_argv == "NV12") {
    return V4L2_PIX_FMT_NV12;
  } else {  // upper_argv == "MJPEG"
    return V4L2_PIX_FMT_MJPEG;
  }
}

namespace {

constexpr auto kDefaultTimeout = base::Seconds(5);

// TODO(b/151047930): Test hotplugging with vivid.
bool IsVividLoaded() {
  std::string output;
  if (!base::GetAppOutput({"lsmod"}, &output)) {
    return false;
  }

  std::vector<base::StringPiece> lines = base::SplitStringPieceUsingSubstr(
      output, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  return std::any_of(lines.begin(), lines.end(), [](const auto& line) {
    return base::StartsWith(line, "vivid", base::CompareCase::SENSITIVE);
  });
}

const std::array<cros_cam_format_info_t, 2> GetTestFormats() {
  // TODO(b/151047930): Wait for vivid to be loaded in Tast test.
  static bool vivid_loaded = IsVividLoaded();
  if (vivid_loaded) {
    // vivid is an upstream Linux kernel module we use for testing and only
    // supports 640x480 up to 25fps.
    return {{{V4L2_PIX_FMT_NV12, 640, 480, 25},
             {V4L2_PIX_FMT_MJPEG, 640, 480, 25}}};
  } else {
    // All camera modules on Chrome OS are required to support this.
    return {{{V4L2_PIX_FMT_NV12, 640, 480, 30},
             {V4L2_PIX_FMT_MJPEG, 640, 480, 30}}};
  }
}

cros_cam_format_info_t GetTestFormat() {
  auto test_formats = GetTestFormats();
  EXPECT_GE(test_formats.size(), 1u);
  return test_formats[0];
}

}  // namespace

class ConnectorEnvironment : public ::testing::Environment {
 public:
  void SetUp() override {
    static constexpr char kTestClientTokenPath[] =
        "/run/camera_tokens/testing/token";

    base::FilePath token_path(kTestClientTokenPath);
    std::string token_string;
    ASSERT_TRUE(base::ReadFileToString(token_path, &token_string))
        << "Failed to read token from " << kTestClientTokenPath;
    const cros_cam_init_option_t option = {
        .api_version = 1,
        .token = token_string.c_str(),
    };
    ASSERT_EQ(cros_cam_init(&option), 0);
    LOGF(INFO) << "Camera connector initialized";
  }

  void TearDown() override {
    EXPECT_EQ(cros_cam_exit(), 0);
    LOGF(INFO) << "Camera connector exited";
  }
};

class FrameCapturer {
 public:
  FrameCapturer() : thread_("FrameCapturer") { thread_.Start(); }
  ~FrameCapturer() { thread_.Stop(); }

  FrameCapturer& SetNumFrames(int num_frames) {
    num_frames_ = num_frames;
    return *this;
  }

  FrameCapturer& SetDuration(base::TimeDelta duration) {
    duration_ = duration;
    return *this;
  }

  // Run starts a capture session with the given |id| and |format|. Returns the
  // number of frames captured or the error status if an error is encountered.
  int Run(int id, cros_cam_format_info_t format) {
    auto future = cros::Future<int>::Create(nullptr);
    thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&FrameCapturer::RunAsync, base::Unretained(this), id,
                       std::move(format), cros::GetFutureCallback(future)));
    return future->Get();
  }

  // Run starts a capture session with the given |id| and |format|. Fires
  // |callback| with the number of frames captured or the error status if an
  // error is encountered.
  void RunAsync(int id,
                cros_cam_format_info_t format,
                base::OnceCallback<void(int)> callback) {
    int ret = StartCapture(id, std::move(format));
    if (ret != 0) {
      LOGF(ERROR) << "Failed to start capture";
      std::move(callback).Run(ret);
      return;
    }
    thread_.task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&FrameCapturer::WaitForCaptureResult,
                                  base::Unretained(this), std::move(callback)));
  }

  I420Buffer LastI420Frame() const { return last_i420_frame_; }

 private:
  int StartCapture(int id, cros_cam_format_info_t format) {
    num_frames_captured_ = 0;
    last_status_ = 0;
    capture_done_.Reset();

    id_ = id;
    format_ = format;
    const cros_cam_capture_request_t request = {
        .id = id,
        .format = &format,
    };
    return cros_cam_start_capture(&request, &FrameCapturer::CaptureCallback,
                                  this);
  }

  void WaitForCaptureResult(base::OnceCallback<void(int)> callback) {
    // Wait until |duration_| passed or |num_frames_| captured. Fires |callback|
    // with the number of frames captured or the error status if an error is
    // encountered.
    if (!capture_done_.TimedWait(duration_)) {
      cros_cam_stop_capture(id_);
      capture_done_.Signal();
    }
    LOGF(INFO) << "Last status = " << last_status_;
    LOGF(INFO) << "Captured " << num_frames_captured_ << " frames";
    std::move(callback).Run(last_status_ != 0 ? last_status_
                                              : num_frames_captured_);
  }

  // Non-zero return value should stop the capture.
  int GotCaptureResult(const cros_cam_capture_result_t* result) {
    if (capture_done_.IsSignaled()) {
      ADD_FAILURE() << "got capture result after capture is done";
      return -1;
    }

    if (result->status != 0) {
      LOGF(WARNING) << "Capture result error: "
                    << base::safe_strerror(-result->status);
      last_status_ = result->status;
      capture_done_.Signal();
      return -1;
    }

    const cros_cam_frame_t* frame = result->frame;
    EXPECT_TRUE(IsSameFormat(frame->format, format_));
    last_i420_frame_ = I420Buffer::Create(frame);

    num_frames_captured_++;
    if (num_frames_captured_ == num_frames_) {
      capture_done_.Signal();
      return -1;
    }

    return 0;
  }

  static int CaptureCallback(void* context,
                             const cros_cam_capture_result_t* result) {
    static base::Time last_frame_time = base::Time::Now();
    base::TimeDelta frame_interval = base::Time::Now() - last_frame_time;
    last_frame_time = base::Time::Now();
    VLOGF(1) << "Frame interval: " << frame_interval.InMilliseconds() << " ms";

    auto* self = reinterpret_cast<FrameCapturer*>(context);
    return self->GotCaptureResult(result);
  }

  base::Thread thread_;

  int num_frames_ = INT_MAX;
  base::TimeDelta duration_ = kDefaultTimeout;
  int id_;
  cros_cam_format_info_t format_;

  int num_frames_captured_;
  base::WaitableEvent capture_done_;
  I420Buffer last_i420_frame_;
  int last_status_;
};

class CameraClient {
 public:
  void ProbeCameraInfo() {
    ASSERT_EQ(cros_cam_get_cam_info(&CameraClient::GetCamInfoCallback, this),
              0);
    EXPECT_GT(GetNumberOfCameras(), 0) << "no camera found";
    // All connected cameras should be already reported by the callback
    // function, set the frozen flag to capture unexpected hotplug events
    // during test. Please see the comment of cros_cam_get_cam_info() for more
    // details.
    camera_info_frozen_ = true;
  }

  void DumpCameraInfo() {
    for (const auto& info : camera_infos_) {
      LOGF(INFO) << "id: " << info.id;
      LOGF(INFO) << "name: " << info.name;
      LOGF(INFO) << "facing: " << FacingToString(info.facing);
      LOGF(INFO) << "format_count: " << info.format_count;
      for (int i = 0; i < info.format_count; i++) {
        LOGF(INFO) << base::StringPrintf(
            "Format %2d: %s", i,
            CameraFormatInfoToString(info.format_info[i]).c_str());
      }
    }
  }

  size_t GetNumberOfCameras() { return camera_infos_.size(); }

  int FindIdForFormat(const cros_cam_format_info_t& format) {
    for (const auto& info : camera_infos_) {
      for (int i = 0; i < info.format_count; i++) {
        if (IsSameFormat(format, info.format_info[i])) {
          return info.id;
        }
      }
    }
    return -1;
  }

  void RestartCrosCamera() {
    prev_num_cameras_ = GetNumberOfCameras();
    camera_info_frozen_ = false;
    // We don't clear |camera_infos_| here expecting that libcamera_connector
    // would notify us that the cameras are down.
    init_done_event_.Reset();
    LOGF(INFO) << "Restarting cros-camera";
    ASSERT_EQ(system("stop cros-camera"), 0) << "Failed to stop camera";
    ASSERT_EQ(system("start cros-camera"), 0) << "Failed to start camera";
    ASSERT_TRUE(init_done_event_.TimedWait(kDefaultTimeout))
        << "Failed to get all camera info after timeout";
  }

 private:
  int GotCameraInfo(const cros_cam_info_t* info, int is_removed) {
    EXPECT_FALSE(camera_info_frozen_) << "unexpected hotplug events";
    if (is_removed) {
      LOGF(INFO) << "Camera " << info->id << " removed";
      // TODO(lnishan): Check return value of base::EraseIf after libchrome in
      // Chrome OS includes crrev.com/c/2072038.
      size_t old_size = camera_infos_.size();
      base::EraseIf(camera_infos_, [&](const auto& my_info) {
        return my_info.id == info->id;
      });
      CHECK_EQ(camera_infos_.size(), old_size - 1);
    } else {
      LOGF(INFO) << "Got camera info for camera " << info->id;
      EXPECT_GT(info->format_count, 0) << "no available formats";
      camera_infos_.push_back(*info);
      if (GetNumberOfCameras() == prev_num_cameras_) {
        init_done_event_.Signal();
      }
    }
    return 0;
  }

  static int GetCamInfoCallback(void* context,
                                const cros_cam_info_t* info,
                                int is_removed) {
    auto* self = reinterpret_cast<CameraClient*>(context);
    return self->GotCameraInfo(info, is_removed);
  }
  std::vector<cros_cam_info_t> camera_infos_;
  bool camera_info_frozen_ = false;
  int prev_num_cameras_ = -1;
  base::WaitableEvent init_done_event_;
};

class CaptureTest
    : public ::testing::Test,
      public ::testing::WithParamInterface<cros_cam_format_info_t> {
 protected:
  void SetUp() override {
    client_.ProbeCameraInfo();
    format_ = GetParam();
    camera_id_ = client_.FindIdForFormat(format_);
    ASSERT_NE(camera_id_, -1);
  }

  CameraClient client_;
  FrameCapturer capturer_;

  int camera_id_;
  cros_cam_format_info_t format_;
};

TEST(ConnectorTest, GetInfo) {
  CameraClient client1;
  client1.ProbeCameraInfo();
  client1.DumpCameraInfo();

  // Check that we can unsubscribe the info callback.
  ASSERT_EQ(0, cros_cam_get_cam_info(nullptr, nullptr));

  CameraClient client2;
  client2.ProbeCameraInfo();
  ASSERT_EQ(client1.GetNumberOfCameras(), client2.GetNumberOfCameras());
}

TEST_P(CaptureTest, OneFrame) {
  int num_frames_captured = capturer_.SetNumFrames(1).Run(camera_id_, format_);
  EXPECT_EQ(num_frames_captured, 1);
}

TEST_P(CaptureTest, ThreeSeconds) {
  const auto kDuration = base::Seconds(3);
  int num_frames_captured =
      capturer_.SetDuration(kDuration).Run(camera_id_, format_);
  // It's expected to get more than 1 frame in 3s.
  EXPECT_GT(num_frames_captured, 1);
}

TEST(DISABLED_CaptureTest, ContinuousCapture) {
  const auto kDuration =
      base::Seconds(g_cont_capture_args.capture_duration_secs);
  cros_cam_format_info_t format = {
      .fourcc = g_cont_capture_args.format,
      .width = static_cast<int>(g_cont_capture_args.capture_size.width),
      .height = static_cast<int>(g_cont_capture_args.capture_size.height),
      .fps = g_cont_capture_args.fps,
  };
  FrameCapturer capturer;
  int num_frames_captured = capturer.SetDuration(kDuration).Run(
      g_cont_capture_args.camera_id, format);
  // It's expected to get more than 1 frame.
  EXPECT_GT(num_frames_captured, 1);
}

TEST(ConnectorTest, CompareFrames) {
  CameraClient client;
  client.ProbeCameraInfo();
  auto test_formats = GetTestFormats();
  CHECK_GE(test_formats.size(), 2u);

  int id = client.FindIdForFormat(test_formats[0]);
  ASSERT_NE(id, -1);

  FrameCapturer capturer;
  capturer.SetNumFrames(1);

  ASSERT_EQ(capturer.Run(id, test_formats[0]), 1);
  I420Buffer frame1 = capturer.LastI420Frame();

  ASSERT_EQ(capturer.Run(id, test_formats[1]), 1);
  I420Buffer frame2 = capturer.LastI420Frame();

  double ssim = libyuv::I420Ssim(
      frame1.DataY(), frame1.StrideY(), frame1.DataU(), frame1.StrideU(),
      frame1.DataV(), frame1.StrideV(), frame2.DataY(), frame2.StrideY(),
      frame2.DataU(), frame2.StrideU(), frame2.DataV(), frame2.StrideV(),
      frame1.Width(), frame1.Height());
  LOGF(INFO) << "ssim = " << ssim;

  // It's expected have two similar but not exactly same frames captured in the
  // short period with MJPEG and NV12. The normal values are around 0.7~0.8.
  EXPECT_GE(ssim, 0.3);

  // If the frames are exactly same (ssim = 1.0), the frame is likely broken
  // such as all pixels are black. Set the threshold as 0.99 for potential jpeg
  // artifacts and floating point error.
  EXPECT_LE(ssim, 0.99);
}

TEST(ConnectorTest, RestartCrosCameraIdle) {
  CameraClient client;
  FrameCapturer capturer;
  auto format = GetTestFormat();

  client.ProbeCameraInfo();
  client.RestartCrosCamera();

  int id = client.FindIdForFormat(format);
  ASSERT_NE(id, -1);
  int num_frames_captured = capturer.SetNumFrames(1).Run(id, format);
  EXPECT_EQ(num_frames_captured, 1);
}

TEST(ConnectorTest, RestartCrosCameraActive) {
  CameraClient client;
  FrameCapturer capturer;
  auto format = GetTestFormat();

  client.ProbeCameraInfo();
  int id = client.FindIdForFormat(format);
  ASSERT_NE(id, -1);

  auto future = cros::Future<int>::Create(nullptr);
  capturer.SetDuration(kDefaultTimeout)
      .RunAsync(id, format, cros::GetFutureCallback(future));
  client.RestartCrosCamera();
  ASSERT_EQ(future->Get(), -ENODEV);
  int num_frames_captured = capturer.SetNumFrames(1).Run(id, format);
  EXPECT_EQ(num_frames_captured, 1);
}

INSTANTIATE_TEST_SUITE_P(ConnectorTest,
                         CaptureTest,
                         ::testing::ValuesIn(GetTestFormats()),
                         [](const auto& info) {
                           const cros_cam_format_info_t& fmt = info.param;
                           return base::StringPrintf(
                               "%s_%ux%u_%ufps",
                               FourccToString(fmt.fourcc).c_str(), fmt.width,
                               fmt.height, fmt.fps);
                         });

}  // namespace cros::tests

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  base::CommandLine::Init(argc, argv);

  brillo::InitLog(brillo::kLogToStderr);
  logging::SetLogItems(/*enable_process_id=*/true, /*enable_thread_id=*/true,
                       /*enable_timestamp=*/true, /*enable_tickcount=*/false);

  ::testing::AddGlobalTestEnvironment(new cros::tests::ConnectorEnvironment());

  DEFINE_int32(duration, 3, "Duration in seconds to capture for");
  DEFINE_int32(camera_id, 0, "ID of the camera to open");
  DEFINE_string(size, "1280x720", "[width]x[height] of the frames to capture");
  DEFINE_int32(fps, 30, "Frame rate to capture with");
  DEFINE_string(format, "NV12", "The pixel format to capture with");
  brillo::FlagHelper::Init(argc, argv, "CaptureTest.ContinuousCapture args");

  cros::tests::g_cont_capture_args = {
      .capture_duration_secs = FLAGS_duration,
      .camera_id = FLAGS_camera_id,
      .capture_size = cros::tests::ParseSize(FLAGS_size),
      .fps = FLAGS_fps,
      .format = cros::tests::ParseFormat(FLAGS_format),
  };

  return RUN_ALL_TESTS();
}
