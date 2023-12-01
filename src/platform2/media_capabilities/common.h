// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_CAPABILITIES_COMMON_H_
#define MEDIA_CAPABILITIES_COMMON_H_

#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>

enum class CameraDescription : int32_t {
  kNone = 0,
  kBuiltinUSBCamera,
  kBuiltinMIPICamera,
  kVividCamera,
  kBuiltinCamera,
  kBuiltinOrVividCamera,
};

enum class Profile : int32_t {
  kNone = 0,
  // TODO(hiroh): Think about adding h264 constrained baseline.
  kH264Baseline,
  kH264Main,
  kH264High,
  kVP8,
  kVP9Profile0,
  kVP9Profile2,
  kAV1Main,
  // TODO(b/172229001): Add HEVC and HEVC10 profiles.
  kJPEG,
};

enum class Resolution : int32_t {
  kNone = 0,
  k1080p,  // 1920x1080
  k2160p,  // 3840x2160
};

enum class Subsampling : int32_t {
  kNone = 0,
  kYUV420,
  kYUV422,
  kYUV444,
};

enum class ColorDepth : int32_t {
  kNone = 0,
  k8bit,
  k10bit,
};

// TODO(b/172229001): Add encryption enum.

class Capability {
 public:
  // For codec capability.
  Capability(Profile profile,
             bool decode,
             Resolution resolution,
             Subsampling subsampling,
             ColorDepth color_depth);
  // For camera capability.
  explicit Capability(CameraDescription camera_description);
  ~Capability() = default;
  Capability(const Capability&) = default;
  Capability& operator=(const Capability&) = default;

  bool operator<(const Capability& other) const;
  bool operator==(const Capability& other) const;
  bool operator!=(const Capability& other) const;
  std::string ToString() const;

 private:
  CameraDescription camera_description_;
  Profile profile_;
  bool decode_;
  Resolution resolution_;
  Subsampling subsampling_;
  ColorDepth color_depth_;
};

// Gets paths of all existing files (not directories) with the specified prefix,
// |absolute_path|. For instance, if "/dev/video" is given, /dev/video0 and
// /dev/video-dec0 are returned if they exist.
std::vector<base::FilePath> GetAllFilesWithPrefix(
    const base::FilePath& absolute_path);

// Executes an ioctl() retrying in case of a signal interruption.
int Ioctl(int fd, uint32_t request, void* args);

// Gets all Resolutions that are less than or equal to |resolution|.
std::vector<Resolution> GetInterestingResolutionsUpTo(
    const std::pair<int, int>& resolution);
#endif  // MEDIA_CAPABILITIES_COMMON_H_
