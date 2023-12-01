/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <string>
#include <vector>

#include <base/containers/contains.h>
#include <base/strings/string_util.h>
#include <base/strings/string_number_conversions.h>

#include "cros-camera/common.h"
#include "hal/fake/hal_spec.h"
#include "hal/fake/value_util.h"

namespace cros {

namespace {

constexpr char kCamerasKey[] = "cameras";
constexpr char kIdKey[] = "id";
constexpr char kConnectedKey[] = "connected";
constexpr char kSupportedFormatsKey[] = "supported_formats";
constexpr char kWidthKey[] = "width";
constexpr char kHeightKey[] = "height";
constexpr char kFrameRatesKey[] = "frame_rates";
constexpr char kFramesKey[] = "frames";
constexpr char kPathKey[] = "path";
constexpr char kScaleModeKey[] = "scale_mode";

constexpr char kScaleModeStretch[] = "stretch";
constexpr char kScaleModeCover[] = "cover";
constexpr char kScaleModeContain[] = "contain";

// Default fps ranges, this conform to the minimal required fps ranges as in
// https://developer.android.com/reference/android/hardware/camera2/CameraCharacteristics#CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES
const std::vector<std::pair<int, int>> kDefaultFpsRanges = {{15, 60}, {60, 60}};

FramesSpec ParseFramesSpec(const DictWithPath& frames_value) {
  if (auto path = GetRequiredValue<std::string>(frames_value, kPathKey)) {
    ScaleMode scale_mode = ScaleMode::kStretch;
    if (auto scale_mode_str =
            GetValue<std::string>(frames_value, kScaleModeKey)) {
      if (*scale_mode_str == kScaleModeCover) {
        scale_mode = ScaleMode::kCover;
      } else if (*scale_mode_str == kScaleModeContain) {
        scale_mode = ScaleMode::kContain;
      } else if (*scale_mode_str != kScaleModeStretch) {
        LOGF(WARNING) << "invalid scale mode " << *scale_mode_str << " at "
                      << frames_value.path << "." << kScaleModeKey
                      << ", fallback to stretch";
      }
    }
    return FramesFileSpec{base::FilePath(*path), scale_mode};
  }
  return FramesTestPatternSpec();
}

// Parses an entry in frame_rates array of the supported formats.
// The supported formats are: 60 (int), [60] (list of one int), [60, 120] (list
// of two ints).
std::optional<std::pair<int, int>> ParseFrameRate(
    const ValueWithPath& frame_rate) {
  int low, high;
  if (auto fps_range_value = GetIfList(frame_rate)) {
    std::vector<int> values;
    bool valid = true;
    for (const auto& raw_value : *fps_range_value) {
      auto value = raw_value->GetIfInt();
      if (!value) {
        valid = false;
        break;
      }
      values.push_back(*value);
      if (values.size() > 2) {
        valid = false;
        break;
      }
    }
    if (!valid || values.size() == 0) {
      LOGF(WARNING) << "invalid frame_rate range " << fps_range_value->value
                    << " at " << fps_range_value->path << ", ignore";
      return std::nullopt;
    }
    // We accept either [fps] or [low, high] for fps range.
    if (values.size() == 1) {
      low = values[0];
      high = values[0];
    } else if (values.size() == 2) {
      low = values[0];
      high = values[1];
    } else {
      NOTREACHED();
      return std::nullopt;
    }
  } else if (auto fps_value = frame_rate->GetIfInt()) {
    low = *fps_value;
    high = *fps_value;
  } else {
    LOGF(WARNING) << "unknown type of frame_rate " << frame_rate.value << " at "
                  << frame_rate.path << ", ignore";
    return std::nullopt;
  }
  if (low <= 0 || high < low) {
    LOGF(WARNING) << "invalid frame_rate range: " << low << " " << high
                  << " at " << frame_rate.path << ", ignore";
    return std::nullopt;
  }
  return std::make_pair(low, high);
}

std::vector<SupportedFormatSpec> ParseSupportedFormatSpecs(
    const ListWithPath& supported_formats_value) {
  std::vector<SupportedFormatSpec> supported_formats;
  // TODO(pihsun): This currently might not satisfy the requirement, since
  // 240p, 480p, 720p might be missing.
  for (const auto& c : supported_formats_value) {
    auto supported_format_value = GetIfDict(c);
    if (!supported_format_value.has_value()) {
      continue;
    }
    SupportedFormatSpec supported_format;
    if (auto width =
            GetRequiredValue<int>(*supported_format_value, kWidthKey)) {
      supported_format.width = *width;
    } else {
      continue;
    }
    if (auto height =
            GetRequiredValue<int>(*supported_format_value, kHeightKey)) {
      supported_format.height = *height;
    } else {
      continue;
    }
    if (auto frame_rates =
            GetValue<ListWithPath>(*supported_format_value, kFrameRatesKey)) {
      for (const auto& frame_rate : *frame_rates) {
        if (const auto& parsed_frame_rate = ParseFrameRate(frame_rate)) {
          supported_format.fps_ranges.push_back(*parsed_frame_rate);
        }
      }
      if (supported_format.fps_ranges.empty()) {
        LOGF(WARNING) << "empty frame_rates at " << frame_rates->path
                      << ", ignore";
        continue;
      }
    } else {
      supported_format.fps_ranges = kDefaultFpsRanges;
    }

    // TODO(pihsun): Support actual format.
    supported_formats.push_back(supported_format);
  }
  return supported_formats;
}

std::vector<CameraSpec> ParseCameraSpecs(const ListWithPath& cameras_value) {
  std::vector<CameraSpec> camera_specs;
  for (auto c : cameras_value) {
    auto spec_value = GetIfDict(c);
    if (!spec_value.has_value()) {
      continue;
    }

    CameraSpec camera_spec;

    if (auto id = GetRequiredValue<int>(*spec_value, kIdKey)) {
      if (base::Contains(camera_specs, *id,
                         [](const CameraSpec& spec) { return spec.id; })) {
        LOGF(WARNING) << "duplicated id " << *id << " at " << spec_value->path
                      << ".id, ignore";
        continue;
      }
      camera_spec.id = *id;
    } else {
      // TODO(pihsun): Use generated ID for this case?
      continue;
    }
    camera_spec.connected =
        GetValue<bool>(*spec_value, kConnectedKey).value_or(false);

    if (auto frames = GetValue<DictWithPath>(*spec_value, kFramesKey)) {
      camera_spec.frames = ParseFramesSpec(*frames);
    } else {
      camera_spec.frames = FramesTestPatternSpec();
    }

    if (auto supported_formats =
            GetValue<ListWithPath>(*spec_value, kSupportedFormatsKey)) {
      camera_spec.supported_formats =
          ParseSupportedFormatSpecs(*supported_formats);
      if (camera_spec.supported_formats.empty()) {
        LOGF(WARNING) << "empty supported_formats at "
                      << supported_formats->path << ", ignore";
        continue;
      }
    } else {
      // Using default supported formats.
      // Resolutions are the required ones in
      // https://chromeos.google.com/partner/dlm/docs/latest-requirements/chromebook.html#cam-sw-0003-v01
      camera_spec.supported_formats = {
          {
              .width = 320,
              .height = 240,
              .fps_ranges = kDefaultFpsRanges,
          },
          {
              .width = 640,
              .height = 360,
              .fps_ranges = kDefaultFpsRanges,
          },
          {
              .width = 640,
              .height = 480,
              .fps_ranges = kDefaultFpsRanges,
          },
          {
              .width = 1280,
              .height = 720,
              .fps_ranges = kDefaultFpsRanges,
          },
          {
              .width = 1280,
              .height = 960,
              .fps_ranges = kDefaultFpsRanges,
          },
          {
              .width = 1920,
              .height = 1080,
              .fps_ranges = kDefaultFpsRanges,
          },
      };
    }

    camera_specs.push_back(camera_spec);
  }
  return camera_specs;
}

}  // namespace

std::optional<HalSpec> ParseHalSpecFromJsonValue(
    const base::Value::Dict& value) {
  HalSpec spec;

  DictWithPath root = {&value, {}};

  if (auto cameras = GetRequiredValue<ListWithPath>(root, kCamerasKey)) {
    spec.cameras = ParseCameraSpecs(*cameras);
  }

  return spec;
}
}  // namespace cros
