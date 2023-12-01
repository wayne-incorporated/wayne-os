/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_HAL_SPEC_H_
#define CAMERA_HAL_FAKE_HAL_SPEC_H_

#include <optional>
#include <utility>
#include <variant>
#include <vector>

#include <base/files/file_path.h>
#include <base/values.h>

namespace cros {

// Specify how to scale the given frame image into target resolution.
enum class ScaleMode {
  // Stretch the image to the target resolution.
  kStretch,
  // Resize the image to the largest size that will fit in the target
  // resolution while maintaining the aspect ratio. The result image will be
  // center aligned and outside area filled by black.
  kContain,
  // Resize the image to the smallest size that will cover the target
  // resolution while maintaining the aspect ratio. The result image will be
  // center aligned and the excessive area trimmed.
  kCover,
};

struct SupportedFormatSpec {
  int width = 0;
  int height = 0;
  std::vector<std::pair<int, int>> fps_ranges;

  bool operator==(const SupportedFormatSpec& rhs) const {
    return width == rhs.width && height == rhs.height &&
           fps_ranges == rhs.fps_ranges;
  }
  bool operator!=(const SupportedFormatSpec& rhs) const {
    return !(*this == rhs);
  }
};

struct FramesFileSpec {
  base::FilePath path;
  ScaleMode scale_mode;

  bool operator==(const FramesFileSpec& rhs) const {
    return path == rhs.path && scale_mode == rhs.scale_mode;
  }
  bool operator!=(const FramesFileSpec& rhs) const { return !(*this == rhs); }
};

struct FramesTestPatternSpec {
  bool operator==(const FramesTestPatternSpec& rhs) const { return true; }
  bool operator!=(const FramesTestPatternSpec& rhs) const {
    return !(*this == rhs);
  }
};

using FramesSpec = std::variant<FramesFileSpec, FramesTestPatternSpec>;

struct CameraSpec {
  int id = 0;
  bool connected = false;
  std::vector<SupportedFormatSpec> supported_formats;
  FramesSpec frames = FramesTestPatternSpec();
};

struct HalSpec {
  std::vector<CameraSpec> cameras;
};

std::optional<HalSpec> ParseHalSpecFromJsonValue(
    const base::Value::Dict& value);

}  // namespace cros

#endif  // CAMERA_HAL_FAKE_HAL_SPEC_H_
