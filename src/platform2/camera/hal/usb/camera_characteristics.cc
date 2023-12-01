/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/camera_characteristics.h"

#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/no_destructor.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <re2/re2.h>

#include "cros-camera/common.h"
#include "cros-camera/timezone.h"
#include "hal/usb/quirks.h"

namespace cros {

// TODO(shik): Should we replace the custom format by proto/json/yaml/toml/xml?

namespace {

bool IsUsbV1Key(const std::string& key) {
  static const std::set<std::string> kV1Keys = {
      "resolution_1280x960_unsupported",
      "resolution_1600x1200_unsupported",
      "allow_external_camera",
  };
  return kV1Keys.count(key);
}

template <typename T>
void ParseSize(const std::string& value, T* width, T* height) {
  CHECK(RE2::FullMatch(value, "(.*)x(.*)", width, height));
}

template <typename T>
Rect<T> ParseRect(const std::string& value) {
  T left, top, right, bottom;
  CHECK(RE2::FullMatch(value, "(.*),(.*),(.*),(.*)", &left, &top, &right,
                       &bottom));
  Rect<T> rect(left, top, right - left, bottom - top);
  CHECK(rect.is_valid());
  return rect;
}

template <typename T>
std::vector<T> ParseCommaSeparated(const std::string& value) {
  std::vector<std::string> values = base::SplitString(
      value, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  size_t n = values.size();
  std::vector<T> res(n);
  for (size_t i = 0; i < n; i++) {
    CHECK(std::istringstream(values[i]) >> res[i])
        << "Failed to parse " << values[i];
  }
  return res;
}

uint32_t ParseQuirks(const std::string& value) {
  static const base::NoDestructor<std::map<std::string, uint32_t>> kNameMap(
      std::map<std::string, uint32_t>{
          {"prefer_mjpeg", kQuirkPreferMjpeg},
          {"report_least_fps_ranges", kQuirkReportLeastFpsRanges},
          {"v1device", kQuirkV1Device},
          {"android_external", kQuirkAndroidExternal},
          {"android_legacy", kQuirkAndroidLegacy},
      });
  std::vector<std::string> names = base::SplitString(
      value, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  uint32_t quirks = 0;
  for (const auto& name : names) {
    auto it = kNameMap->find(name);
    CHECK(it != kNameMap->end()) << "Invalid quirk name " << name;
    quirks |= it->second;
  }
  return quirks;
}

void SetEntry(const std::string& key,
              const std::string& value,
              DeviceInfo* info) {
  // Follow the same order as defined in common_types.h
  if (key == "usb_vid_pid") {
    CHECK(RE2::FullMatch(value, "([0-9a-f]{4}):([0-9a-f]{4})", &info->usb_vid,
                         &info->usb_pid));
  } else if (key == "frames_to_skip_after_streamon") {
    info->frames_to_skip_after_streamon = stoi(value);
  } else if (key == "constant_framerate_unsupported") {
    std::istringstream(value) >> std::boolalpha >>
        info->constant_framerate_unsupported;
  } else if (key == "quirks") {
    info->quirks |= ParseQuirks(value);
  } else if (key == "lens_facing") {
    info->lens_facing = static_cast<LensFacing>(stoi(value));
  } else if (key == "sensor_orientation") {
    int sensor_orientation = stoi(value);
    if (sensor_orientation != 0) {
      LOGF(FATAL) << "sensor_orientation is set to a non-zero value: "
                  << sensor_orientation;
    }
    LOGF(WARNING) << "sensor_orientation is deprecated";
  } else if (key == "lens_info_available_apertures") {
    info->lens_info_available_apertures = ParseCommaSeparated<float>(value);
  } else if (key == "lens_info_available_focal_lengths") {
    info->lens_info_available_focal_lengths = ParseCommaSeparated<float>(value);
  } else if (key == "lens_info_minimum_focus_distance") {
    info->lens_info_minimum_focus_distance = stof(value);
  } else if (key == "lens_info_optimal_focus_distance") {
    info->lens_info_optimal_focus_distance = stof(value);
  } else if (key == "sensor_info_physical_size") {
    ParseSize(value, &info->sensor_info_physical_size_width,
              &info->sensor_info_physical_size_height);
  } else if (key == "sensor_info_pixel_array_size") {
    ParseSize(value, &info->sensor_info_pixel_array_size_width,
              &info->sensor_info_pixel_array_size_height);
  } else if (key == "sensor_info_active_array_size") {
    info->sensor_info_active_array_size = ParseRect<int32_t>(value);
  } else if (key == "horizontal_view_angle_16_9") {
    info->horizontal_view_angle_16_9 = stof(value);
  } else if (key == "horizontal_view_angle_4_3") {
    info->horizontal_view_angle_4_3 = stof(value);
  } else if (key == "vertical_view_angle_16_9") {
    info->vertical_view_angle_16_9 = stof(value);
  } else if (key == "vertical_view_angle_4_3") {
    info->vertical_view_angle_4_3 = stof(value);
  } else if (key == "enable_face_detection") {
    std::istringstream(value) >> std::boolalpha >> info->enable_face_detection;
  } else if (IsUsbV1Key(key)) {
    VLOGF(1) << "Ignored v1 key: " << key << " value: " << value;
  } else {
    LOGF(FATAL) << "Unknown key: " << key << " value: " << value;
  }
}

}  // namespace

// static
bool CameraCharacteristics::ConfigFileExists() {
  return base::PathExists(kCameraCharacteristicsConfigFile);
}

CameraCharacteristics::CameraCharacteristics() {
  if (ConfigFileExists()) {
    InitFrom(kCameraCharacteristicsConfigFile);
  }
}

CameraCharacteristics::CameraCharacteristics(
    const base::FilePath& config_file) {
  InitFrom(config_file);
}

void CameraCharacteristics::InitFrom(const base::FilePath& config_file) {
  CHECK(base::PathExists(config_file))
      << config_file.value() << " does not exist";
  std::ifstream ifs(config_file.value());
  CHECK(ifs.good()) << "Can't open file " << config_file.value();

  // Used as per_camera_infos[camera_id].
  DeviceInfos per_camera_infos;

  // Used as per_module_infos[camera_id][module_id].
  std::vector<DeviceInfos> per_module_infos;

  for (std::string line; std::getline(ifs, line);) {
    line = base::ToLowerASCII(base::TrimWhitespaceASCII(line, base::TRIM_ALL));

    // Skip empty lines and comments.
    if (line.empty() || line[0] == '#') {
      continue;
    }

    size_t camera_id, module_id;
    std::string key, value;

    if (RE2::FullMatch(line, R"(camera(\d+)\.([^.=]+)=(.+))", &camera_id, &key,
                       &value)) {
      // camera{x}.{key}={value}
      if (camera_id == per_camera_infos.size()) {
        per_camera_infos.push_back({.camera_id = static_cast<int>(camera_id)});
        per_module_infos.push_back({});
      }
      CHECK(camera_id + 1 == per_camera_infos.size())
          << "Invalid camera id " << camera_id;
      CHECK(per_module_infos.back().empty())
          << "Module specific characteristics should come after camera "
             "specific ones";

      SetEntry(key, value, &per_camera_infos[camera_id]);
    } else if (RE2::FullMatch(line, R"(camera(\d+)\.module(\d+).([^.=]+)=(.+))",
                              &camera_id, &module_id, &key, &value)) {
      // camera{x}.module{y}.{key}={value}
      DeviceInfos& module_infos = per_module_infos[camera_id];
      if (module_id == module_infos.size()) {
        module_infos.push_back(per_camera_infos[camera_id]);
      }
      CHECK(module_id + 1 == module_infos.size())
          << "Invalid module id " << module_id;

      SetEntry(key, value, &module_infos[module_id]);
    } else {
      LOGF(FATAL) << "Failed to parse: " << line;
    }
  }

  for (const auto& camera_infos : per_module_infos) {
    for (const auto& module_info : camera_infos) {
      auto ret = camera_module_infos_.insert(
          {{module_info.usb_vid, module_info.usb_pid}, module_info});
      CHECK(ret.second) << "Duplicate vid:pid in config";
    }
  }
}

const DeviceInfo* CameraCharacteristics::Find(const std::string& vid,
                                              const std::string& pid) const {
  auto it = camera_module_infos_.find({vid, pid});
  if (it != camera_module_infos_.end()) {
    const DeviceInfo& info = it->second;
    VLOGF(1) << "Found camera" << info.camera_id << " in characteristics"
             << " with vid:pid = " << vid << ":" << pid;
    return &it->second;
  } else {
    VLOGF(1) << "No camera with vid:pid = " << vid << ":" << pid
             << " found in characteristics";
    return nullptr;
  }
}

}  // namespace cros
