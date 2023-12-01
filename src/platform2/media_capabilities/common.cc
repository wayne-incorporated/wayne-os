// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_capabilities/common.h"

#include <sys/ioctl.h>

#include <base/files/file_enumerator.h>
#include <base/logging.h>
#include <base/numerics/safe_conversions.h>
#include <base/posix/eintr_wrapper.h>

int Ioctl(int fd, uint32_t request, void* arg) {
  return HANDLE_EINTR(ioctl(fd, request, arg));
}

std::vector<Resolution> GetInterestingResolutionsUpTo(
    const std::pair<int, int>& resolution) {
  const int width = resolution.first;
  const int height = resolution.second;
  std::vector<Resolution> lower_resolutions;
  if (1920 <= width && 1080 <= height)
    lower_resolutions.push_back(Resolution::k1080p);
  if (3840 <= width && 2160 <= height)
    lower_resolutions.push_back(Resolution::k2160p);
  return lower_resolutions;
}

std::vector<base::FilePath> GetAllFilesWithPrefix(
    const base::FilePath& absolute_path) {
  LOG_ASSERT(absolute_path.IsAbsolute())
      << absolute_path << " is not absolute path";
  base::FilePath root_path;
  base::FilePath base_name;
  if (absolute_path.EndsWithSeparator()) {
    root_path = absolute_path;
  } else {
    root_path = absolute_path.DirName();
    base_name = absolute_path.BaseName();
  }
  base::FileEnumerator enumerator(root_path, /*recursive=*/false,
                                  base::FileEnumerator::FILES,
                                  base_name.value() + std::string("*"));
  std::vector<base::FilePath> matched_paths;
  for (base::FilePath path = enumerator.Next(); !path.empty();
       path = enumerator.Next()) {
    matched_paths.push_back(path);
  }
  return matched_paths;
}

Capability::Capability(Profile profile,
                       bool decode,
                       Resolution resolution,
                       Subsampling subsampling,
                       ColorDepth color_depth)
    : camera_description_(CameraDescription::kNone),
      profile_(profile),
      decode_(decode),
      resolution_(resolution),
      subsampling_(subsampling),
      color_depth_(color_depth) {}

Capability::Capability(CameraDescription camera_description)
    : camera_description_(camera_description),
      profile_(Profile::kNone),
      decode_(false),
      resolution_(Resolution::kNone),
      subsampling_(Subsampling::kNone),
      color_depth_(ColorDepth::kNone) {}

bool Capability::operator<(const Capability& other) const {
  if (camera_description_ != other.camera_description_) {
    return static_cast<int32_t>(camera_description_) <
           static_cast<int32_t>(other.camera_description_);
  }
  if (profile_ != other.profile_) {
    return static_cast<int32_t>(profile_) <
           static_cast<int32_t>(other.profile_);
  }

  // When sorting, we want decode capabilities to appear before encode
  // capabilities (no particular reason).
  if (decode_ != other.decode_)
    return decode_ > other.decode_;

  if (resolution_ != other.resolution_) {
    return static_cast<int32_t>(resolution_) <
           static_cast<int32_t>(other.resolution_);
  }
  if (subsampling_ != other.subsampling_) {
    return static_cast<int32_t>(subsampling_) <
           static_cast<int32_t>(other.subsampling_);
  }
  return static_cast<int32_t>(color_depth_) <
         static_cast<int32_t>(other.color_depth_);
}

bool Capability::operator==(const Capability& other) const {
  return !((*this < other) || (other < *this));
}

bool Capability::operator!=(const Capability& other) const {
  return !(*this == other);
}

std::string Capability::ToString() const {
  switch (camera_description_) {
    case CameraDescription::kNone:
      // Codec capability.
      break;
    case CameraDescription::kBuiltinUSBCamera:
      return "builtin_usb_camera";
    case CameraDescription::kBuiltinMIPICamera:
      return "builtin_mipi_camera";
    case CameraDescription::kVividCamera:
      return "vivid_camera";
    case CameraDescription::kBuiltinCamera:
      return "builtin_camera";
    case CameraDescription::kBuiltinOrVividCamera:
      return "builtin_or_vivid_camera";
  }

  std::string output;
  switch (profile_) {
    case Profile::kNone:
      LOG(FATAL) << "Profile must be specified in codec capability";
      return "Invalid";
    case Profile::kH264Baseline:
      output = "h264_baseline";
      break;
    case Profile::kH264Main:
      output = "h264_main";
      break;
    case Profile::kH264High:
      output = "h264_high";
      break;
    case Profile::kVP8:
      output = "vp8";
      break;
    case Profile::kVP9Profile0:
      output = "vp9_0";
      break;
    case Profile::kVP9Profile2:
      output = "vp9_2";
      break;
    case Profile::kAV1Main:
      output = "av1_main";
      break;
    case Profile::kJPEG:
      output = "jpeg";
      break;
  }

  output += decode_ ? "_decode" : "_encode";

  switch (resolution_) {
    case Resolution::kNone:
      LOG(FATAL) << "Resolution must be specified";
      return "Invalid";
    case Resolution::k1080p:
      output += "_1080p";
      break;
    case Resolution::k2160p:
      output += "_2160p";
      break;
  }

  switch (subsampling_) {
    case Subsampling::kNone:
      LOG(FATAL) << "Subsampling must be specified";
      return "Invalid";
    case Subsampling::kYUV420:
      // Regular subsampling. Nothing is appended.
      break;
    case Subsampling::kYUV422:
      output += "_422";
      break;
    case Subsampling::kYUV444:
      output += "_444";
      break;
  }

  switch (color_depth_) {
    case ColorDepth::kNone:
      LOG(FATAL) << "Color depth must be specified";
      break;
    case ColorDepth::k8bit:
      // Regular color depth. Nothing is appended.
      break;
    case ColorDepth::k10bit:
      output += "_10bpp";
      break;
  }

  return output;
}
