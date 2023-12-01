// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <linux/v4l2-controls.h>

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/timer/elapsed_timer.h>
#include <base/time/time.h>
#include <brillo/flag_helper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libyuv.h>

#include "cros-camera/common.h"
#include "cros-camera/device_config.h"
#include "hal/usb/camera_characteristics.h"
#include "hal/usb/common_types.h"
#include "hal/usb/tests/media_v4l2_device.h"

namespace cros {
namespace tests {

class V4L2TestEnvironment;

namespace {

using ::testing::AnyOf;
using ::testing::StrEq;
using ::testing::GTEST_FLAG(filter);
using ::testing::MatchesRegex;

V4L2TestEnvironment* g_env;

// Test lists:
// default: for devices without ARC++, and devices with ARC++ which use
//          camera HAL v1.
// halv3: for devices with ARC++ which use camera HAL v3.
// certification: for third-party labs to verify new camera modules.

constexpr char kDefaultTestList[] = "default";
constexpr char kHalv3TestList[] = "halv3";
constexpr char kCertificationTestList[] = "certification";
// Correctness check the V4L2_SEL_TGT_ROI_BOUNDS_MIN value. 320x320 is very
// large.
constexpr uint32_t kMaxMinRoiWidth = 320;
constexpr uint32_t kMaxMinRoiHeight = 320;

struct UsbInfo {
  std::string vid_pid;
  std::string bcd_device;
};

UsbInfo GetUsbInfo(const base::FilePath& path) {
  auto read_id = [&](const char* name) -> std::string {
    base::FilePath id_path(
        base::StringPrintf("/sys/class/video4linux/%s/device/../%s",
                           path.BaseName().value().c_str(), name));
    base::FilePath normalized;
    if (!base::NormalizeFilePath(id_path, &normalized)) {
      return "";
    }
    std::string id;
    if (!base::ReadFileToString(normalized, &id)) {
      return "";
    }
    return std::string(base::TrimWhitespaceASCII(id, base::TRIM_ALL));
  };
  return UsbInfo{
      .vid_pid = read_id("idVendor") + ":" + read_id("idProduct"),
      .bcd_device = read_id("bcdDevice"),
  };
}

bool IsCaptureDevice(const base::FilePath& path) {
  const uint32_t kCaptureMask =
      V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_VIDEO_CAPTURE_MPLANE;
  // Old drivers use (CAPTURE | OUTPUT) for memory-to-memory video devices.
  const uint32_t kOutputMask =
      V4L2_CAP_VIDEO_OUTPUT | V4L2_CAP_VIDEO_OUTPUT_MPLANE;
  const uint32_t kM2mMask = V4L2_CAP_VIDEO_M2M | V4L2_CAP_VIDEO_M2M_MPLANE;

  V4L2Device dev(path.value().c_str(), 1);
  if (!dev.OpenDevice(/*show_err=*/false)) {
    return false;
  }
  v4l2_capability caps;
  if (!dev.ProbeCaps(&caps, false)) {
    return false;
  }
  uint32_t mask = (caps.capabilities & V4L2_CAP_DEVICE_CAPS)
                      ? caps.device_caps
                      : caps.capabilities;
  return (mask & kCaptureMask) && !(mask & kOutputMask) && !(mask & kM2mMask);
}

bool IsUsbCamera(const base::FilePath& path) {
  return IsCaptureDevice(path) && !GetUsbInfo(path).vid_pid.empty();
}

bool IsBuiltinUsbCamera(const base::FilePath& path) {
  if (!IsUsbCamera(path)) {
    return false;
  }
  std::string vid_pid = GetUsbInfo(path).vid_pid;
  CameraCharacteristics characteristics;
  const DeviceInfo* device_info =
      characteristics.Find(vid_pid.substr(0, 4), vid_pid.substr(5, 9));
  return device_info != nullptr;
}

std::vector<base::FilePath> GetDevices(
    base::RepeatingCallback<bool(const base::FilePath&)> selector) {
  std::vector<base::FilePath> devices;
  base::FilePath pattern("/dev/video*");
  base::FileEnumerator enumerator(pattern.DirName(), false,
                                  base::FileEnumerator::FILES,
                                  pattern.BaseName().value());
  for (auto path = enumerator.Next(); !path.empty(); path = enumerator.Next()) {
    if (selector.Run(path)) {
      devices.push_back(path);
    }
  }
  std::sort(devices.begin(), devices.end());
  return devices;
}

void AddNegativeGtestFilter(const std::string& pattern) {
  if (GTEST_FLAG(filter).find(pattern) == std::string::npos) {
    LOGF(INFO) << "Disable test " << pattern;
    char has_dash = GTEST_FLAG(filter).find('-') != std::string::npos;
    GTEST_FLAG(filter).append(has_dash ? ":" : "-").append(pattern);
  }
}

// This is for Android SurfaceViewPreviewTest CTS test cases.
bool CheckTimestampsInOrder(const std::vector<int64_t>& timestamps) {
  std::vector<size_t> out_of_order_ids;
  for (size_t i = 1; i < timestamps.size(); i++) {
    if (timestamps[i - 1] >= timestamps[i])
      out_of_order_ids.push_back(i);
  }
  if (out_of_order_ids.empty()) {
    return true;
  }
  LOGF(ERROR) << "Found out-of-order timestamps:";
  constexpr size_t kTap = 2;
  size_t next_id = 0;
  DCHECK_GT(timestamps.size(), 0);
  for (size_t i : out_of_order_ids) {
    for (size_t j = std::max(next_id, i - std::min(i, kTap));
         j <= std::min(i + kTap, timestamps.size() - 1); ++j) {
      if (j > next_id) {
        LOGF(ERROR) << "  ...";
      }
      LOGF(ERROR) << "  [" << j << "] " << timestamps[j];
      next_id = j + 1;
    }
  }
  return false;
}

// This is for Android testCameraToSurfaceTextureMetadata CTS test case.
bool CheckConstantFramerate(const std::vector<int64_t>& timestamps,
                            float require_fps,
                            bool is_certification) {
  // Timestamps are from driver. If |is_certification| is set true, we only
  // allow 1.5% error buffer for the frame duration. The margin is aligned to
  // CTS tests. If |is_certification| is set false, we allow 5.0% error buffer
  // to avoid test failures in the lab.
  float slop_margin = is_certification ? 0.015 : 0.05;
  float slop_max_frame_duration_ms = (1e3 / require_fps) * (1 + slop_margin);
  float slop_min_frame_duration_ms = (1e3 / require_fps) * (1 - slop_margin);

  for (size_t i = 1; i < timestamps.size(); i++) {
    float frame_duration_ms = (timestamps[i] - timestamps[i - 1]) / 1e6;
    if (frame_duration_ms > slop_max_frame_duration_ms ||
        frame_duration_ms < slop_min_frame_duration_ms) {
      LOGF(WARNING) << base::StringPrintf(
          "Frame duration %f out of frame rate bounds [%f, %f]",
          frame_duration_ms, slop_min_frame_duration_ms,
          slop_max_frame_duration_ms);
      return false;
    }
  }
  return true;
}

bool HasFrameRate(const SupportedFormat& format, float target) {
  return std::any_of(
      format.frame_rates.begin(), format.frame_rates.end(), [&](float fps) {
        return abs(fps - target) <= std::numeric_limits<float>::epsilon();
      });
}

float GetMaxFrameRate(const SupportedFormat& format) {
  return *std::max_element(format.frame_rates.begin(),
                           format.frame_rates.end());
}

bool CompareFormat(const SupportedFormat& fmt1, const SupportedFormat& fmt2) {
  auto get_key = [](const SupportedFormat& fmt)
      -> std::tuple<uint32_t, uint32_t, float, int> {
    uint32_t area = fmt.width * fmt.height;
    float max_fps = GetMaxFrameRate(fmt);
    int fourcc = [&] {
      switch (fmt.fourcc) {
        case V4L2_PIX_FMT_YUYV:
          return 2;
        case V4L2_PIX_FMT_MJPEG:
          return 1;
        default:
          return 0;
      }
    }();
    return {area, fmt.width, max_fps, fourcc};
  };
  return get_key(fmt1) > get_key(fmt2);
}

bool IsSameRect(const v4l2_rect& rect1, const v4l2_rect& rect2) {
  return rect1.top == rect2.top && rect1.left == rect2.left &&
         rect1.height == rect2.height && rect1.width == rect2.width;
}

}  // namespace

class V4L2TestEnvironment : public ::testing::Environment {
 public:
  V4L2TestEnvironment(const std::string& test_list,
                      const std::string& device_path)
      : test_list_(test_list),
        device_path_(device_path),
        usb_info_(GetUsbInfo(base::FilePath(device_path))) {
    std::string model = []() -> std::string {
      std::optional<DeviceConfig> config = DeviceConfig::Create();
      if (!config) {
        LOGF(WARNING) << "Failed to initialize CrOS config";
        return std::string();
      }
      return config->GetModelName();
    }();
    // The WFC maximum supported resolution requirement is waived on some
    // models (b/158564147).
    if ((model == "blacktip360" && usb_info_.vid_pid == "0408:5192") ||
        (model == "garg360" && usb_info_.vid_pid == "0408:5194")) {
      AddNegativeGtestFilter("V4L2Test.MaximumSupportedResolution");
    }
    // We should not allow more than 1s for ReconfigureStreamLatency test.
    // Therefore, disable these tests for some models that take unusual time
    // to reconfigure. ReconfigureAndOneCaptureLatency test does not have a
    // strict time restriction but should run fast enough to pass the test.
    // (b/262473731)
    if ((model == "collis" && usb_info_.vid_pid == "13d3:5521") ||
        (model == "jelboz360" && usb_info_.vid_pid == "13d3:5521") ||
        (model == "dood" && usb_info_.vid_pid == "0408:3029")) {
      AddNegativeGtestFilter("V4L2Test.ReconfigureStreamLatency");
      AddNegativeGtestFilter(
          "V4L2Test/V4L2ReconfigureTest.ReconfigureAndOneCaptureLatency*");
    }

    // The gtest filter need to be modified before RUN_ALL_TESTS().
    if (test_list == kDefaultTestList) {
      // Disable new requirements added in HALv3.
      AddNegativeGtestFilter("V4L2Test.FirstFrameAfterStreamOn");
      AddNegativeGtestFilter("V4L2Test.CroppingResolution");

      // Some snappy old SKU cannot meet the requirement. Skip the test to
      // avoid alarm. Please see http://crbug.com/737874 for detail.
      if (base::SysInfo::GetLsbReleaseBoard() == "snappy") {
        AddNegativeGtestFilter("V4L2Test.MaximumSupportedResolution");
      }
      // The camera module sometimes generate out-of-order buffer timestamps.
      // See b/158957477 for detail.
      if (usb_info_.vid_pid == "0c45:6a05") {
        check_timestamps_in_order_ = false;
      }
    } else if (test_list == kCertificationTestList) {
      // There is no facing information when running certification test.
      AddNegativeGtestFilter("V4L2Test.MaximumSupportedResolution");
      AddNegativeGtestFilter("V4L2Test.AutoFocusSupported");
    } else if (test_list == kHalv3TestList) {
      // The camera modules do not support 1080p 30fps and got waived.
      // Please see http://b/142289821 and http://b/115453284 for the detail.
      if (usb_info_.vid_pid == "04f2:b6b5" ||
          usb_info_.vid_pid == "0bda:5647") {
        check_1920x1080_ = false;
        AddNegativeGtestFilter("V4L2Test.CroppingResolution");
      }
    }
  }

  void SetUp() {
    ASSERT_THAT(usb_info_.vid_pid, MatchesRegex("[0-9a-f]{4}:[0-9a-f]{4}"));

    LOGF(INFO) << "Test list: " << test_list_;
    LOGF(INFO) << "Device path: " << device_path_;
    LOGF(INFO) << "USB id: " << usb_info_.vid_pid;
    LOGF(INFO) << "USB bcdDevice: " << usb_info_.bcd_device;

    ASSERT_THAT(test_list_,
                AnyOf(StrEq(kDefaultTestList), StrEq(kHalv3TestList),
                      StrEq(kCertificationTestList)));
    ASSERT_TRUE(base::PathExists(base::FilePath(device_path_)));

    CameraCharacteristics characteristics;
    const DeviceInfo* device_info = characteristics.Find(
        usb_info_.vid_pid.substr(0, 4), usb_info_.vid_pid.substr(5, 9));

    if (test_list_ != kDefaultTestList) {
      ASSERT_TRUE(characteristics.ConfigFileExists())
          << test_list_ << " test list needs camera config file";
      ASSERT_NE(device_info, nullptr)
          << usb_info_.vid_pid << " is not described in camera config file";
    } else {
      if (!characteristics.ConfigFileExists()) {
        LOGF(INFO) << "Camera config file doesn't exist";
      } else if (device_info == nullptr && !usb_info_.vid_pid.empty()) {
        LOGF(INFO) << usb_info_.vid_pid
                   << " is not described in camera config file";
      }
    }

    // Get parameter from config file.
    if (device_info) {
      support_constant_framerate_ =
          !device_info->constant_framerate_unsupported;
      skip_frames_ = device_info->frames_to_skip_after_streamon;
      lens_facing_ = device_info->lens_facing;

      // If there is a camera config and test list is not HAL v1, then we can
      // check cropping requirement according to the sensor physical size.
      if (test_list_ != kDefaultTestList) {
        if (device_info->sensor_info_active_array_size.is_valid()) {
          sensor_array_size_width_ =
              device_info->sensor_info_active_array_size.width;
          sensor_array_size_height_ =
              device_info->sensor_info_active_array_size.height;
        } else {
          LOGF(WARNING) << "Sensor active array size is not available in camera"
                           " config file, using full pixel array size";
          sensor_array_size_width_ =
              device_info->sensor_info_pixel_array_size_width;
          sensor_array_size_height_ =
              device_info->sensor_info_pixel_array_size_height;
        }
      }

      check_roi_control_ = device_info->enable_face_detection;
    }

    if (test_list_ == kDefaultTestList) {
      check_1280x960_ = false;
      check_1600x1200_ = false;
      check_constant_framerate_ = false;
    } else {
      check_1280x960_ = true;
      check_1600x1200_ = true;
      check_constant_framerate_ = true;
      if (skip_frames_ != 0) {
        // Some existing HALv3 boards are using this field to workaround issues
        // that are not caught in this test, such as:
        // * corrupted YUYV frames, and
        // * broken JPEG image when setting power frequency to 60Hz.
        // Although it's infeasible to test every possible parameter
        // combinations, we might want to add tests for the failing cases above
        // in the future and qualify the existing devices.
        LOGF(WARNING) << "Ignore non-zero skip frames for v3 devices";
        skip_frames_ = 0;
      }
      ASSERT_TRUE(support_constant_framerate_)
          << "HALv3 devices should support constant framerate";
    }

    LOGF(INFO) << "Check 1280x960: " << std::boolalpha << check_1280x960_;
    LOGF(INFO) << "Check 1600x1200: " << std::boolalpha << check_1600x1200_;
    LOGF(INFO) << "Check 1920x1080: " << std::boolalpha << check_1920x1080_;
    LOGF(INFO) << "Check constant framerate: " << std::boolalpha
               << check_constant_framerate_;
    LOGF(INFO) << "Number of skip frames after stream on: " << skip_frames_;
  }

  std::string test_list_;
  std::string device_path_;
  UsbInfo usb_info_;

  bool check_1280x960_ = false;
  bool check_1600x1200_ = false;
  bool check_1920x1080_ = true;
  bool check_constant_framerate_ = false;
  bool check_timestamps_in_order_ = true;
  bool check_roi_control_ = false;

  bool support_constant_framerate_ = false;
  uint32_t skip_frames_ = 0;
  LensFacing lens_facing_ = LensFacing::kFront;
  uint32_t sensor_array_size_width_ = 0;
  uint32_t sensor_array_size_height_ = 0;
};

class V4L2Test : public ::testing::Test {
 protected:
  V4L2Test() : dev_(g_env->device_path_.c_str(), 4) {}

  void SetUp() override { ASSERT_TRUE(dev_.OpenDevice()); }

  void TearDown() override { dev_.CloseDevice(); }

  void ProbeSupportedFormats() {
    uint32_t num_format = 0;
    dev_.EnumFormat(&num_format, false);
    for (uint32_t i = 0; i < num_format; ++i) {
      SupportedFormat format;
      ASSERT_TRUE(dev_.GetPixelFormat(i, &format.fourcc));

      uint32_t num_frame_size;
      ASSERT_TRUE(dev_.EnumFrameSize(format.fourcc, &num_frame_size, false));

      for (uint32_t j = 0; j < num_frame_size; ++j) {
        ASSERT_TRUE(
            dev_.GetFrameSize(j, format.fourcc, &format.width, &format.height));
        uint32_t num_frame_rate;
        ASSERT_TRUE(dev_.EnumFrameInterval(format.fourcc, format.width,
                                           format.height, &num_frame_rate,
                                           false));

        format.frame_rates.clear();
        for (uint32_t k = 0; k < num_frame_rate; ++k) {
          float frame_rate;
          ASSERT_TRUE(dev_.GetFrameInterval(k, format.fourcc, format.width,
                                            format.height, &frame_rate));
          // All supported resolution should have at least 1 fps.
          ASSERT_GE(frame_rate, 1.0);
          format.frame_rates.push_back(frame_rate);
        }
        supported_formats_.push_back(format);
      }
    }

    std::sort(supported_formats_.begin(), supported_formats_.end(),
              CompareFormat);
  }

  const SupportedFormats& GetSupportedFormats() {
    if (supported_formats_.empty()) {
      ProbeSupportedFormats();
    }
    return supported_formats_;
  }

  // Find format according to width and height. If multiple formats support the
  // same resolution, choose the first one.
  const SupportedFormat* FindSupportedFormat(uint32_t width,
                                             uint32_t height,
                                             float fps) {
    for (const auto& format : GetSupportedFormats()) {
      if (format.width == width && format.height == height &&
          HasFrameRate(format, fps)) {
        return &format;
      }
    }
    return nullptr;
  }

  // Find format according to V4L2 fourcc. If multiple resolution support the
  // same fourcc, choose the first one.
  const SupportedFormat* FindFormatByFourcc(uint32_t fourcc) {
    for (const auto& format : supported_formats_) {
      if (format.fourcc == fourcc) {
        return &format;
      }
    }
    return nullptr;
  }

  SupportedFormat GetMaximumResolution() {
    SupportedFormat max_format;
    for (const auto& format : GetSupportedFormats()) {
      if (format.width >= max_format.width) {
        max_format.width = format.width;
      }
      if (format.height >= max_format.height) {
        max_format.height = format.height;
      }
    }
    return max_format;
  }

  const SupportedFormat* GetResolutionForCropping(float fps) {
    // FOV requirement cannot allow cropping twice. If two streams resolution
    // are 1920x1080 and 1600x1200, we need a larger resolution which aspect
    // ratio is the same as sensor aspect ratio.
    float sensor_aspect_ratio =
        static_cast<float>(g_env->sensor_array_size_width_) /
        g_env->sensor_array_size_height_;

    // We need to compare the aspect ratio from sensor resolution.
    // The sensor resolution may not be just the size. It may be a little
    // larger. Add a margin to check if the sensor aspect ratio fall in the
    // specific aspect ratio. 16:9=1.778, 16:10=1.6, 3:2=1.5, 4:3=1.333
    const float kAspectRatioMargin = 0.04;

    for (const auto& format : GetSupportedFormats()) {
      if (format.width < 1920 || format.height < 1200 ||
          !HasFrameRate(format, fps)) {
        continue;
      }
      float aspect_ratio = static_cast<float>(format.width) / format.height;
      if (std::abs(sensor_aspect_ratio - aspect_ratio) < kAspectRatioMargin) {
        return &format;
      }
    }
    return nullptr;
  }

  bool ExerciseControl(uint32_t id, const char* control) {
    v4l2_queryctrl query_ctrl;
    if (!dev_.QueryControl(id, &query_ctrl)) {
      LOGF(WARNING) << "Cannot query control name: " << control;
      return false;
    }
    if (!dev_.SetControl(id, query_ctrl.maximum)) {
      LOGF(WARNING) << "Cannot set " << control << " to maximum value";
    }
    if (!dev_.SetControl(id, query_ctrl.minimum)) {
      LOGF(WARNING) << "Cannot set " << control << " to minimum value";
    }
    if (!dev_.SetControl(id, query_ctrl.default_value)) {
      LOGF(WARNING) << "Cannot set " << control << " to default value";
    }
    return true;
  }

  bool ExerciseROI() {
    v4l2_selection selection;
    v4l2_selection selection_min;
    v4l2_selection selection_max;
    if (!dev_.GetSelection(V4L2_SEL_TGT_ROI_BOUNDS_MIN, &selection_min)) {
      LOGF(ERROR) << "Cannot get select V4L2_SEL_TGT_ROI_BOUNDS_MIN";
      return false;
    }
    if (selection_min.r.width > kMaxMinRoiWidth ||
        selection_min.r.height > kMaxMinRoiHeight) {
      LOGF(ERROR) << "V4L2_SEL_TGT_ROI_BOUNDS_MIN: " << selection_min.r.width
                  << "x" << selection_min.r.height << " is too large.";
      return false;
    }
    // The minimum bounds defines the ROI minimum rectangle size. Only the width
    // and height are meaningful. The left and top values are all 0s.
    if (selection_min.r.left != 0 || selection_min.r.top != 0) {
      LOGF(ERROR) << "V4L2_SEL_TGT_ROI_BOUNDS_MIN(left, top):("
                  << selection_min.r.left << "," << selection_min.r.top
                  << ") != (0,0).";
      return false;
    }
    if (!dev_.GetSelection(V4L2_SEL_TGT_ROI_BOUNDS_MAX, &selection_max)) {
      LOGF(ERROR) << "Cannot get select V4L2_SEL_TGT_ROI_BOUNDS_MAX";
      return false;
    }
    if (selection_max.r.width <= selection_min.r.width ||
        selection_max.r.height <= selection_min.r.height) {
      LOGF(ERROR) << "V4L2_SEL_TGT_ROI_BOUNDS_MAX: " << selection_max.r.width
                  << "x" << selection_max.r.height << " is too small.";
      return false;
    }
    SupportedFormat max_resolution = GetMaximumResolution();
    if (selection_max.r.width < max_resolution.width ||
        selection_max.r.height < max_resolution.height) {
      LOGF(ERROR) << "V4L2_SEL_TGT_ROI_BOUNDS_MAX: " << selection_max.r.width
                  << "x" << selection_max.r.height
                  << " is less than: " << max_resolution.width << "x"
                  << max_resolution.height;
      return false;
    }
    if (!dev_.GetSelection(V4L2_SEL_TGT_ROI_DEFAULT, &selection)) {
      LOGF(ERROR) << "Cannot get select V4L2_SEL_TGT_ROI_DEFAULT";
      return false;
    }
    if (selection.r.width < selection_min.r.width ||
        selection.r.height < selection_min.r.height) {
      LOGF(ERROR) << "V4L2_SEL_TGT_ROI_DEFAULT: " << selection.r.width << "x"
                  << selection.r.height << " is too small.";
      return false;
    }
    if (selection.r.width > selection_max.r.width ||
        selection.r.height > selection_max.r.height) {
      LOGF(ERROR) << "V4L2_SEL_TGT_ROI_DEFAULT: " << selection.r.width << "x"
                  << selection.r.height << " is too large.";
      return false;
    }
    if (selection.r.top < selection_max.r.top ||
        selection.r.left < selection_max.r.left) {
      LOGF(ERROR) << "V4L2_SEL_TGT_ROI_DEFAULT(left, top):(" << selection.r.left
                  << "," << selection.r.top << ") is out of range ("
                  << selection_max.r.left << "," << selection_max.r.top << ").";
      return false;
    }

    v4l2_rect rect = {
        .left = 10,
        .top = 20,
        .width = (selection_min.r.width + selection_max.r.width) / 2,
        .height = (selection_min.r.height + selection_max.r.height) / 2,
    };
    if (!dev_.SetSelection(V4L2_SEL_TGT_ROI, rect)) {
      LOGF(ERROR) << "Cannot set select V4L2_SEL_TGT_ROI";
      return false;
    }
    if (!dev_.GetSelection(V4L2_SEL_TGT_ROI, &selection)) {
      LOGF(ERROR) << "Cannot get select V4L2_SEL_TGT_ROI";
      return false;
    }
    if (!IsSameRect(rect, selection.r)) {
      LOGF(ERROR) << "V4L2_SEL_TGT_ROI set and get mismatch";
      return false;
    }

    // ROI should remain unchanged after resolution change.
    SupportedFormat format = max_resolution;
    for (const SupportedFormat& fmt : GetSupportedFormats()) {
      // Picking a format that's different from the current/max resolution.
      // We've seen some camera modules unexpectedly change the ROI with it.
      if (fmt.width != max_resolution.width ||
          fmt.height != max_resolution.height) {
        format = fmt;
        break;
      }
    }
    ExerciseFormat(format.width, format.height, GetMaxFrameRate(format));

    v4l2_selection new_selection;
    if (!dev_.GetSelection(V4L2_SEL_TGT_ROI, &new_selection)) {
      LOGF(ERROR) << "Cannot get select V4L2_SEL_TGT_ROI";
      return false;
    }
    if (!IsSameRect(new_selection.r, selection.r)) {
      LOGF(ERROR) << "V4L2_SEL_TGT_ROI changed after format change";
      return false;
    }

    if (!dev_.GetSelection(V4L2_SEL_TGT_ROI_BOUNDS_MAX, &new_selection)) {
      LOGF(ERROR) << "Cannot get select V4L2_SEL_TGT_ROI_BOUNDS_MAX";
      return false;
    }
    if (!IsSameRect(new_selection.r, selection_max.r)) {
      LOGF(ERROR) << "V4L2_SEL_TGT_ROI_BOUNDS_MAX changed after format change";
      return false;
    }

    if (!dev_.GetSelection(V4L2_SEL_TGT_ROI_BOUNDS_MIN, &new_selection)) {
      LOGF(ERROR) << "Cannot get select V4L2_SEL_TGT_ROI_BOUNDS_MIN";
      return false;
    }
    if (!IsSameRect(new_selection.r, selection_min.r)) {
      LOGF(ERROR) << "V4L2_SEL_TGT_ROI_BOUNDS_MIN changed after format change";
      return false;
    }

    return true;
  }

  void RunCapture(V4L2Device::IOMethod io,
                  uint32_t width,
                  uint32_t height,
                  uint32_t pixfmt,
                  float fps,
                  V4L2Device::ConstantFramerate constant_framerate,
                  uint32_t skip_frames,
                  base::TimeDelta duration) {
    ASSERT_TRUE(dev_.InitDevice(io, width, height, pixfmt, fps,
                                constant_framerate, skip_frames));
    ASSERT_TRUE(dev_.StartCapture());
    ASSERT_TRUE(dev_.Run(duration.InSeconds()));
    ASSERT_TRUE(dev_.StopCapture());
    ASSERT_TRUE(dev_.UninitDevice());

    // Make sure the driver didn't adjust the format.
    v4l2_format fmt = {};
    ASSERT_TRUE(dev_.GetV4L2Format(&fmt));
    ASSERT_EQ(width, fmt.fmt.pix.width);
    ASSERT_EQ(height, fmt.fmt.pix.height);
    ASSERT_EQ(pixfmt, fmt.fmt.pix.pixelformat);
    ASSERT_FLOAT_EQ(fps, dev_.GetFrameRate());
  }

  void ExerciseFormat(uint32_t width, uint32_t height, float fps) {
    const int kMaxRetryTimes = 5;
    const auto duration = base::Seconds(3);

    std::vector<V4L2Device::ConstantFramerate> constant_framerates;
    if (g_env->check_constant_framerate_) {
      constant_framerates = {V4L2Device::ENABLE_CONSTANT_FRAMERATE,
                             V4L2Device::DISABLE_CONSTANT_FRAMERATE};
    } else {
      constant_framerates = {V4L2Device::DEFAULT_FRAMERATE_SETTING};
    }

    const SupportedFormat* test_format =
        FindSupportedFormat(width, height, fps);
    ASSERT_NE(test_format, nullptr)
        << width << "x" << height << " at " << fps << " fps is not supported";

    for (const auto& constant_framerate : constant_framerates) {
      bool success = false;
      for (int retry_count = 0; retry_count < kMaxRetryTimes; retry_count++) {
        ASSERT_TRUE(dev_.InitDevice(V4L2Device::IO_METHOD_MMAP, width, height,
                                    test_format->fourcc, fps,
                                    constant_framerate, 0));
        ASSERT_TRUE(dev_.StartCapture());
        ASSERT_TRUE(dev_.Run(3));
        ASSERT_TRUE(dev_.StopCapture());
        ASSERT_TRUE(dev_.UninitDevice());

        // Make sure the driver didn't adjust the format.
        v4l2_format fmt = {};
        ASSERT_TRUE(dev_.GetV4L2Format(&fmt));
        ASSERT_EQ(width, fmt.fmt.pix.width);
        ASSERT_EQ(height, fmt.fmt.pix.height);
        ASSERT_EQ(test_format->fourcc, fmt.fmt.pix.pixelformat);
        ASSERT_FLOAT_EQ(fps, dev_.GetFrameRate());

        if (g_env->check_timestamps_in_order_) {
          ASSERT_TRUE(CheckTimestampsInOrder(dev_.GetFrameTimestamps()))
              << base::StringPrintf(
                     "Capture test %dx%d (%08X) failed because frame "
                     "timestamps are out of order",
                     test_format->width, test_format->height,
                     test_format->fourcc);
        }

        if (constant_framerate == V4L2Device::ENABLE_CONSTANT_FRAMERATE) {
          float actual_fps = (dev_.GetNumFrames() - 1) / duration.InSecondsF();
          // 1 fps buffer is because |time_to_capture| may be too short.
          // EX: 30 fps and capture 3 secs. We may get 89 frames or 91 frames.
          // The actual fps will be 29.66 or 30.33.
          if (abs(actual_fps - fps) > 1) {
            LOGF(WARNING) << base::StringPrintf(
                "Capture test %dx%d (%08X) failed with fps %.2f",
                test_format->width, test_format->height, test_format->fourcc,
                actual_fps);
            continue;
          }

          if (!CheckConstantFramerate(
                  dev_.GetFrameTimestamps(), fps,
                  g_env->test_list_ == kCertificationTestList)) {
            LOGF(WARNING) << base::StringPrintf(
                "Capture test %dx%d (%08X) failed and didn't meet "
                "constant framerate",
                test_format->width, test_format->height, test_format->fourcc);
            continue;
          }
        }

        success = true;
        break;
      }
      EXPECT_TRUE(success) << "Cannot meet constant framerate requirement for "
                           << kMaxRetryTimes << " times";
    }
  }

  V4L2Device dev_;
  SupportedFormats supported_formats_;
};

class V4L2TestWithIO
    : public V4L2Test,
      public ::testing::WithParamInterface<V4L2Device::IOMethod> {};

class V4L2TestWithResolution
    : public V4L2Test,
      public ::testing::WithParamInterface<std::pair<uint32_t, uint32_t>> {};

TEST_F(V4L2Test, MultipleOpen) {
  V4L2Device dev2(g_env->device_path_.c_str(), 4);
  ASSERT_TRUE(dev2.OpenDevice()) << "Cannot open device for the second time";
  dev2.CloseDevice();
}

TEST_P(V4L2TestWithIO, MultipleInit) {
  V4L2Device::IOMethod io = GetParam();
  V4L2Device::ConstantFramerate constant_framerate =
      V4L2Device::DEFAULT_FRAMERATE_SETTING;
  V4L2Device& dev1 = dev_;
  V4L2Device dev2(g_env->device_path_.c_str(), 4);
  ASSERT_TRUE(dev2.OpenDevice()) << "Cannot open device for the second time";

  ASSERT_TRUE(dev1.InitDevice(io, 640, 480, V4L2_PIX_FMT_YUYV, 30,
                              constant_framerate, 0))
      << "Cannot init device for the first time";

  ASSERT_FALSE(dev2.InitDevice(io, 640, 480, V4L2_PIX_FMT_YUYV, 30,
                               constant_framerate, 0))
      << "Multiple init device should fail";

  dev1.UninitDevice();
  dev2.UninitDevice();
  dev2.CloseDevice();
}

INSTANTIATE_TEST_SUITE_P(V4L2Test,
                         V4L2TestWithIO,
                         ::testing::Values(V4L2Device::IO_METHOD_MMAP,
                                           V4L2Device::IO_METHOD_USERPTR));

// EnumInput and EnumStandard are optional.
TEST_F(V4L2Test, EnumInputAndStandard) {
  dev_.EnumInput();
  dev_.EnumStandard();
}

// EnumControl is optional, but the output is useful. For example, we could
// know whether constant framerate is supported or not.
TEST_F(V4L2Test, EnumControl) {
  dev_.EnumControl();
}

TEST_F(V4L2Test, SetControl) {
  // Test mandatory controls.
  if (g_env->check_constant_framerate_) {
    ASSERT_TRUE(ExerciseControl(V4L2_CID_EXPOSURE_AUTO_PRIORITY,
                                "exposure_auto_priority"));
  }

  // Test optional controls.
  ExerciseControl(V4L2_CID_BRIGHTNESS, "brightness");
  ExerciseControl(V4L2_CID_CONTRAST, "contrast");
  ExerciseControl(V4L2_CID_SATURATION, "saturation");
  ExerciseControl(V4L2_CID_GAMMA, "gamma");
  ExerciseControl(V4L2_CID_HUE, "hue");
  ExerciseControl(V4L2_CID_GAIN, "gain");
  ExerciseControl(V4L2_CID_SHARPNESS, "sharpness");
}

TEST_F(V4L2Test, SetROI) {
  if (g_env->check_roi_control_) {
    ExerciseControl(V4L2_CID_REGION_OF_INTEREST_AUTO, "roi auto");
    ASSERT_TRUE(ExerciseROI());
  } else {
    GTEST_SKIP() << "Skipped because enable_face_detection is not set";
  }
}

// SetCrop is optional.
TEST_F(V4L2Test, SetCrop) {
  v4l2_cropcap cropcap = {};
  if (dev_.GetCropCap(&cropcap)) {
    v4l2_crop crop = {};
    crop.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    crop.c = cropcap.defrect;
    dev_.SetCrop(&crop);
  }
}

// GetCrop is optional.
TEST_F(V4L2Test, GetCrop) {
  v4l2_crop crop = {};
  crop.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  dev_.GetCrop(&crop);
}

TEST_F(V4L2Test, ProbeCaps) {
  v4l2_capability caps;
  ASSERT_TRUE(dev_.ProbeCaps(&caps, true));
  uint32_t dev_caps = (caps.capabilities & V4L2_CAP_DEVICE_CAPS)
                          ? caps.device_caps
                          : caps.capabilities;
  ASSERT_TRUE(dev_caps & V4L2_CAP_VIDEO_CAPTURE)
      << "Should support video capture interface";
}

TEST_F(V4L2Test, EnumFormats) {
  ASSERT_TRUE(dev_.EnumFormat(NULL));
}

TEST_F(V4L2Test, EnumFrameSize) {
  uint32_t format_count = 0;
  ASSERT_TRUE(dev_.EnumFormat(&format_count));
  for (uint32_t i = 0; i < format_count; i++) {
    uint32_t pixfmt;
    ASSERT_TRUE(dev_.GetPixelFormat(i, &pixfmt));
    ASSERT_TRUE(dev_.EnumFrameSize(pixfmt, NULL));
  }
}

TEST_F(V4L2Test, EnumFrameInterval) {
  uint32_t format_count = 0;
  ASSERT_TRUE(dev_.EnumFormat(&format_count));
  for (uint32_t i = 0; i < format_count; i++) {
    uint32_t pixfmt;
    ASSERT_TRUE(dev_.GetPixelFormat(i, &pixfmt));
    uint32_t size_count;
    ASSERT_TRUE(dev_.EnumFrameSize(pixfmt, &size_count));

    for (uint32_t j = 0; j < size_count; j++) {
      uint32_t width, height;
      ASSERT_TRUE(dev_.GetFrameSize(j, pixfmt, &width, &height));
      ASSERT_TRUE(dev_.EnumFrameInterval(pixfmt, width, height, NULL));
    }
  }
}

TEST_F(V4L2Test, FrameRate) {
  v4l2_streamparm param;
  ASSERT_TRUE(dev_.GetParam(&param));
  // we only try to adjust frame rate when it claims can.
  if (param.parm.capture.capability & V4L2_CAP_TIMEPERFRAME) {
    ASSERT_TRUE(dev_.SetParam(&param));
  } else {
    LOGF(INFO) << "Does not support TIMEPERFRAME";
  }
}

TEST_F(V4L2Test, CroppingResolution) {
  constexpr float kRequiredFpsForCropping = 30.0f;
  const SupportedFormat* cropping_format =
      GetResolutionForCropping(kRequiredFpsForCropping);
  if (cropping_format == nullptr) {
    SupportedFormat max_resolution = GetMaximumResolution();
    ASSERT_TRUE(max_resolution.width < 1920 || max_resolution.height < 1200)
        << "Cannot find cropping resolution";
    return;
  }
}

TEST_P(V4L2TestWithResolution, Required30FpsResolution) {
  const auto [width, height] = GetParam();
  if (!g_env->check_1280x960_ && width == 1280 && height == 960) {
    GTEST_SKIP() << "Skipped because check_1280x960_ is not set";
  }
  if (!g_env->check_1600x1200_ && width == 1600 && height == 1200) {
    GTEST_SKIP() << "Skipped because check_1600x1200_ is not set";
  }
  if (!g_env->check_1920x1080_ && width == 1920 && height == 1080) {
    GTEST_SKIP() << "Skipped because check_1920x1080_ is not set";
  }
  const SupportedFormat max_resolution = GetMaximumResolution();
  if (width > max_resolution.width || height > max_resolution.height) {
    GTEST_SKIP() << "Skipped because it's larger than maximum resolution";
  }
  const SupportedFormat* format = FindSupportedFormat(width, height, 30.0f);
  EXPECT_NE(format, nullptr)
      << width << "x" << height << " at 30 fps is not supported";
}

// Test all supported resolutions and frame rates.
// If device supports constant framerate, the test will toggle the setting
// and check actual fps. Otherwise, use the default setting of
// V4L2_CID_EXPOSURE_AUTO_PRIORITY.
TEST_F(V4L2Test, SupportedFormats) {
  constexpr uint32_t kMinWidth = 320;
  constexpr uint32_t kMinHeight = 240;
  for (const SupportedFormat& format : GetSupportedFormats()) {
    if (format.width < kMinWidth || format.height < kMinHeight) {
      continue;
    }
    for (float fps : format.frame_rates) {
      ExerciseFormat(format.width, format.height, fps);
    }
  }
}

constexpr std::pair<uint32_t, uint32_t> kTestResolutions[] = {
    {320, 240},  {640, 480},   {1280, 720},
    {1280, 960}, {1600, 1200}, {1920, 1080},
};
INSTANTIATE_TEST_SUITE_P(V4L2Test,
                         V4L2TestWithResolution,
                         ::testing::ValuesIn(kTestResolutions),
                         [](const auto& info) {
                           uint32_t width = std::get<0>(info.param);
                           uint32_t height = std::get<1>(info.param);
                           return base::StringPrintf("%ux%u", width, height);
                         });

// ChromeOS spec requires world-facing camera should be at least 1920x1080 and
// user-facing camera should be at least 1280x720.
TEST_F(V4L2Test, MaximumSupportedResolution) {
  SupportedFormat max_resolution = GetMaximumResolution();

  uint32_t required_width;
  uint32_t required_height;
  std::string facing_str;
  if (g_env->lens_facing_ == LensFacing::kFront) {
    required_width = 1280;
    required_height = 720;
    facing_str = "user";
  } else if (g_env->lens_facing_ == LensFacing::kBack) {
    required_width = 1920;
    required_height = 1080;
    facing_str = "world";
  } else {
    FAIL() << "Invalid facing: " << static_cast<int>(g_env->lens_facing_);
  }

  EXPECT_GE(max_resolution.width, required_width);
  EXPECT_GE(max_resolution.height, required_height);

  if (HasFailure()) {
    LOGF(ERROR) << base::StringPrintf(
        "The maximum resolution %dx%d does not meet the requirement %dx%d for "
        "%s-facing camera",
        max_resolution.width, max_resolution.height, required_width,
        required_height, facing_str.c_str());
  }
}

TEST_F(V4L2Test, FirstFrameAfterStreamOn) {
  const SupportedFormat* test_format = FindFormatByFourcc(V4L2_PIX_FMT_MJPEG);
  if (test_format == nullptr) {
    GTEST_SKIP() << "Skipped because the camera doesn't support MJPEG format";
  }

  uint32_t width = test_format->width;
  uint32_t height = test_format->height;
  float fps = GetMaxFrameRate(*test_format);

  for (int i = 0; i < 20; i++) {
    ASSERT_TRUE(dev_.InitDevice(
        V4L2Device::IO_METHOD_MMAP, width, height, V4L2_PIX_FMT_MJPEG, fps,
        V4L2Device::DEFAULT_FRAMERATE_SETTING, g_env->skip_frames_));
    ASSERT_TRUE(dev_.StartCapture());

    uint32_t buf_index, data_size;
    int ret;
    do {
      ret = dev_.ReadOneFrame(&buf_index, &data_size);
    } while (ret == 0);
    ASSERT_GT(ret, 0);

    const V4L2Device::Buffer& buffer = dev_.GetBufferInfo(buf_index);
    std::vector<uint8_t> yuv_buffer(width * height * 2);

    int res = libyuv::MJPGToI420(static_cast<uint8_t*>(buffer.start), data_size,
                                 yuv_buffer.data(), width,
                                 yuv_buffer.data() + width * height, width / 2,
                                 yuv_buffer.data() + width * height * 5 / 4,
                                 width / 2, width, height, width, height);
    if (res != 0) {
      base::WriteFile(base::FilePath("FirstFrame.jpg"),
                      static_cast<char*>(buffer.start), data_size);
      FAIL() << "First frame is not a valid mjpeg image.";
    }

    ASSERT_TRUE(dev_.EnqueueBuffer(buf_index));
    ASSERT_TRUE(dev_.StopCapture());
    ASSERT_TRUE(dev_.UninitDevice());
  }
}

// Chrome OS requires that the world-facing camera supports auto-focus. The
// software uses V4L2_CID_FOCUS_AUTO control to toggle auto-focus on/off, which
// maps to the Android AUTO/OFF AF mode.
TEST_F(V4L2Test, AutoFocusSupported) {
  if (g_env->lens_facing_ != LensFacing::kBack)
    GTEST_SKIP();
  ASSERT_TRUE(ExerciseControl(V4L2_CID_FOCUS_AUTO, "focus_auto"));
}

TEST_F(V4L2Test, GetRoiSupport) {
  if (g_env->lens_facing_ == LensFacing::kFront) {
    std::cout << "Facing:front:" << g_env->check_roi_control_ << std::endl;
  } else if (g_env->lens_facing_ == LensFacing::kBack) {
    std::cout << "Facing:back:" << g_env->check_roi_control_ << std::endl;
  } else {
    FAIL() << "Invalid facing: " << static_cast<int>(g_env->lens_facing_);
  }
}

TEST_F(V4L2Test, ReconfigureStreamLatency) {
  constexpr base::TimeDelta kAllowedLatency = base::Milliseconds(1000);

  const SupportedFormat* old_format = FindSupportedFormat(320, 240, 30.0f);

  ASSERT_NE(old_format, nullptr);

  for (const auto& format : GetSupportedFormats()) {
    ASSERT_TRUE(dev_.InitDevice(V4L2Device::IO_METHOD_MMAP, old_format->width,
                                old_format->height, old_format->fourcc, 30.0f,
                                V4L2Device::DEFAULT_FRAMERATE_SETTING, 0));
    ASSERT_TRUE(dev_.StartCapture());
    ASSERT_TRUE(dev_.Run(3));

    base::ElapsedTimer timer;
    ASSERT_TRUE(dev_.StopCapture());
    ASSERT_TRUE(dev_.UninitDevice());
    ASSERT_TRUE(dev_.InitDevice(
        V4L2Device::IO_METHOD_MMAP, format.width, format.height, format.fourcc,
        GetMaxFrameRate(format), V4L2Device::DEFAULT_FRAMERATE_SETTING, 0));
    ASSERT_TRUE(dev_.StartCapture());

    ASSERT_LE(timer.Elapsed(), kAllowedLatency);
    ASSERT_TRUE(dev_.StopCapture());
    ASSERT_TRUE(dev_.UninitDevice());
  }
}

class V4L2ReconfigureTest : public V4L2Test,
                            public ::testing::WithParamInterface<
                                std::tuple<Size, Size, base::TimeDelta>> {};

TEST_P(V4L2ReconfigureTest, ReconfigureAndOneCaptureLatency) {
  const auto& [small_size, large_size, allowed_latency] = GetParam();

  const SupportedFormat* large_format = nullptr;
  for (const auto& format : GetSupportedFormats()) {
    if (format.width == large_size.width &&
        format.height == large_size.height &&
        format.fourcc == static_cast<uint32_t>(V4L2_PIX_FMT_YUYV)) {
      large_format = &format;
    }
  }

  if (!large_format) {
    GTEST_SKIP() << "Device doesn't support resolution "
                 << large_size.ToString();
  }
  const SupportedFormat* small_format =
      FindSupportedFormat(small_size.width, small_size.height, 30.0f);

  ASSERT_NE(small_format, nullptr);

  ASSERT_TRUE(dev_.InitDevice(V4L2Device::IO_METHOD_MMAP, small_format->width,
                              small_format->height, small_format->fourcc, 30.0f,
                              V4L2Device::DEFAULT_FRAMERATE_SETTING, 0));
  ASSERT_TRUE(dev_.StartCapture());
  // Exercise capture with current resolution for 3s.
  ASSERT_TRUE(dev_.Run(3));

  base::ElapsedTimer timer;
  ASSERT_TRUE(dev_.StopCapture());
  ASSERT_TRUE(dev_.UninitDevice());

  ASSERT_TRUE(dev_.InitDevice(V4L2Device::IO_METHOD_MMAP, large_format->width,
                              large_format->height, large_format->fourcc,
                              GetMaxFrameRate(*large_format),
                              V4L2Device::DEFAULT_FRAMERATE_SETTING, 0));
  ASSERT_TRUE(dev_.StartCapture());
  ASSERT_TRUE(dev_.OneCapture());
  ASSERT_TRUE(dev_.StopCapture());
  ASSERT_TRUE(dev_.UninitDevice());

  ASSERT_TRUE(dev_.InitDevice(V4L2Device::IO_METHOD_MMAP, small_format->width,
                              small_format->height, small_format->fourcc, 30.0f,
                              V4L2Device::DEFAULT_FRAMERATE_SETTING, 0));

  ASSERT_TRUE(dev_.StartCapture());
  ASSERT_LE(timer.Elapsed(), allowed_latency);
  ASSERT_TRUE(dev_.StopCapture());
  ASSERT_TRUE(dev_.UninitDevice());
}

INSTANTIATE_TEST_SUITE_P(
    V4L2Test,
    V4L2ReconfigureTest,
    ::testing::ValuesIn(std::vector<std::tuple<Size, Size, base::TimeDelta>>{
        {Size(320, 240), Size(1280, 720), base::Milliseconds(2500)},
        {Size(320, 240), Size(1920, 1080), base::Milliseconds(3500)},
        {Size(320, 240), Size(2592, 1944), base::Milliseconds(3500)}}));
}  // namespace tests
}  // namespace cros

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  DEFINE_bool(list_usbcam, false, "List available USB cameras");
  DEFINE_bool(list_capture_devices, false, "List V4L2 capture devices");
  DEFINE_bool(list_builtin_usbcam, false, "List built-in USB cameras");
  DEFINE_string(test_list, "default", "Select different test list");
  DEFINE_string(device_path, "/dev/video0", "Path to the video device");

  // Add a newline at the beginning of the usage text to separate the help
  // message from gtest.
  brillo::FlagHelper::Init(argc, argv, "\nTest V4L2 camera functionalities.");

  if (FLAGS_list_usbcam && FLAGS_list_capture_devices) {
    LOGF(ERROR) << "|list_usbcam| and |list_capture_devices| cannot be present "
                   "at the same time";
    return -1;
  }

  base::RepeatingCallback<bool(const base::FilePath&)> selector;
  if (FLAGS_list_builtin_usbcam) {
    selector = base::BindRepeating(cros::tests::IsBuiltinUsbCamera);
  } else if (FLAGS_list_usbcam) {
    selector = base::BindRepeating(cros::tests::IsUsbCamera);
  } else if (FLAGS_list_capture_devices) {
    selector = base::BindRepeating(cros::tests::IsCaptureDevice);
  }
  if (!selector.is_null()) {
    std::vector<base::FilePath> devices = cros::tests::GetDevices(selector);
    for (const auto& path : devices) {
      std::cout << path.value() << std::endl;
    }
    return 0;
  }

  cros::tests::g_env =
      new cros::tests::V4L2TestEnvironment(FLAGS_test_list, FLAGS_device_path);
  ::testing::AddGlobalTestEnvironment(cros::tests::g_env);
  return RUN_ALL_TESTS();
}
