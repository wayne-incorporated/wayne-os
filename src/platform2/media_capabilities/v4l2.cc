// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_capabilities/v4l2.h"

#include <fcntl.h>
#include <linux/videodev2.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/contains.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>

#include "media_capabilities/common.h"

namespace {

enum class Codec {
  kH264 = 0,
  kVP8,
  kVP9,
  kJPEG,
  kUnknown,
};

const char* CodecToString(Codec codec) {
  switch (codec) {
    case Codec::kH264:
      return "H264";
    case Codec::kVP8:
      return "VP8";
    case Codec::kVP9:
      return "VP9";
    case Codec::kJPEG:
      return "JPEG";
    default:
      LOG(FATAL) << "Unknown codec: " << static_cast<int>(codec);
      return "";
  }
}

Codec GetCodec(uint32_t format) {
  switch (format) {
    case V4L2_PIX_FMT_H264:
    case V4L2_PIX_FMT_H264_SLICE:
      return Codec::kH264;
    case V4L2_PIX_FMT_VP8:
    case V4L2_PIX_FMT_VP8_FRAME:
      return Codec::kVP8;
    case V4L2_PIX_FMT_VP9:
    case V4L2_PIX_FMT_VP9_FRAME:
      return Codec::kVP9;
    case V4L2_PIX_FMT_JPEG:
      return Codec::kJPEG;
    default:
      return Codec::kUnknown;
  }
}

Profile V4L2ProfileToProfile(Codec codec, uint32_t profile) {
  switch (codec) {
    case Codec::kH264:
      switch (profile) {
        case V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE:
        case V4L2_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_BASELINE:
          return Profile::kH264Baseline;
        case V4L2_MPEG_VIDEO_H264_PROFILE_MAIN:
          return Profile::kH264Main;
        case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH:
          return Profile::kH264High;
        case V4L2_MPEG_VIDEO_H264_PROFILE_EXTENDED:
        case V4L2_MPEG_VIDEO_H264_PROFILE_STEREO_HIGH:
        case V4L2_MPEG_VIDEO_H264_PROFILE_MULTIVIEW_HIGH:
          break;
      }
      break;
    case Codec::kVP8:
      switch (profile) {
        case V4L2_MPEG_VIDEO_VP8_PROFILE_0:
        case V4L2_MPEG_VIDEO_VP8_PROFILE_1:
        case V4L2_MPEG_VIDEO_VP8_PROFILE_2:
        case V4L2_MPEG_VIDEO_VP8_PROFILE_3:
          return Profile::kVP8;
      }
      break;
    case Codec::kVP9:
      switch (profile) {
        case V4L2_MPEG_VIDEO_VP9_PROFILE_0:
          return Profile::kVP9Profile0;
        case V4L2_MPEG_VIDEO_VP9_PROFILE_2:
          return Profile::kVP9Profile2;
        case V4L2_MPEG_VIDEO_VP9_PROFILE_1:
        case V4L2_MPEG_VIDEO_VP9_PROFILE_3:
          break;
      }
      break;
    default:
      break;
  }
  return Profile::kNone;
}

// Return supported profiles for |codec|. If this function is called, a driver
// must support at least one profile because the codec is enumerated by
// VIDIOC_ENUM_FMT.
std::vector<Profile> GetSupportedProfiles(int device_fd, const Codec codec) {
  // Since there is only one JPEG profile, there is no API to acquire the
  // supported JPEG profile. Returns the only JPEG profile.
  if (codec == Codec::kJPEG)
    return {Profile::kJPEG};
  // TODO(b/189169588): Once drivers support V4L2_CID_MPEG_VIDEO_VP8_PROFILE,
  // call VIDIOC_QUERYMENU with it.
  if (codec == Codec::kVP8)
    return {Profile::kVP8};

  uint32_t query_id = 0;
  switch (codec) {
    case Codec::kH264:
      query_id = V4L2_CID_MPEG_VIDEO_H264_PROFILE;
      break;
    case Codec::kVP9:
      query_id = V4L2_CID_MPEG_VIDEO_VP9_PROFILE;
      break;
    case Codec::kVP8:
    case Codec::kJPEG:
    default:
      LOG(FATAL) << "Unknown codec: " << static_cast<uint32_t>(codec);
      return {};
  }

  v4l2_queryctrl query_ctrl;
  memset(&query_ctrl, 0, sizeof(query_ctrl));
  query_ctrl.id = query_id;
  if (Ioctl(device_fd, VIDIOC_QUERYCTRL, &query_ctrl) != 0) {
    PLOG(FATAL) << "VIDIOC_QUERYCTRL failed: ";
    return {};
  }

  std::vector<Profile> profiles;
  v4l2_querymenu query_menu;
  memset(&query_menu, 0, sizeof(query_menu));
  query_menu.id = query_ctrl.id;
  for (query_menu.index = query_ctrl.minimum;
       static_cast<int>(query_menu.index) <= query_ctrl.maximum;
       query_menu.index++) {
    if (Ioctl(device_fd, VIDIOC_QUERYMENU, &query_menu) == 0) {
      const Profile profile = V4L2ProfileToProfile(codec, query_menu.index);
      if (profile != Profile::kNone && !base::Contains(profiles, profile))
        profiles.push_back(profile);
    }
  }

  LOG_IF(FATAL, profiles.empty()) << "No profile is supported even though the "
                                  << "codec is enumerated by VIDIOC_ENUM_FMT";
  return profiles;
}

std::pair<int, int> GetMaxResolution(int device_fd, const uint32_t format) {
  std::pair<int, int> max_resolution(0, 0);
  v4l2_frmsizeenum frame_size;
  memset(&frame_size, 0, sizeof(frame_size));
  frame_size.pixel_format = format;
  for (; Ioctl(device_fd, VIDIOC_ENUM_FRAMESIZES, &frame_size) == 0;
       ++frame_size.index) {
    if (frame_size.type == V4L2_FRMSIZE_TYPE_DISCRETE) {
      if (frame_size.discrete.width >=
              static_cast<uint32_t>(max_resolution.first) &&
          frame_size.discrete.height >=
              static_cast<uint32_t>(max_resolution.second)) {
        max_resolution.first = frame_size.discrete.width;
        max_resolution.second = frame_size.discrete.height;
      }
    } else if (frame_size.type == V4L2_FRMSIZE_TYPE_STEPWISE ||
               frame_size.type == V4L2_FRMSIZE_TYPE_CONTINUOUS) {
      max_resolution.first = frame_size.stepwise.max_width;
      max_resolution.second = frame_size.stepwise.max_height;
      break;
    }
  }

  return max_resolution;
}

std::vector<Capability> GetCapabilitiesInPath(const base::FilePath& path,
                                              bool decode) {
  base::ScopedFD device_fd(
      HANDLE_EINTR(open(path.value().c_str(), O_RDWR | O_CLOEXEC)));
  if (!device_fd.is_valid())
    return {};

  std::vector<uint32_t> formats;
  v4l2_fmtdesc fmtdesc;
  memset(&fmtdesc, 0, sizeof(fmtdesc));
  fmtdesc.type = decode ? V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE
                        : V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
  for (; Ioctl(device_fd.get(), VIDIOC_ENUM_FMT, &fmtdesc) == 0;
       ++fmtdesc.index) {
    formats.push_back(fmtdesc.pixelformat);
  }

  std::vector<Capability> capabilities;
  for (uint32_t format : formats) {
    const Codec codec = GetCodec(format);
    if (codec == Codec::kUnknown)
      continue;

    const std::vector<Profile> profiles =
        GetSupportedProfiles(device_fd.get(), codec);
    LOG_ASSERT(!profiles.empty());
    const std::pair<int, int> max_resolution =
        GetMaxResolution(device_fd.get(), format);
    const std::vector<Resolution> resolutions =
        GetInterestingResolutionsUpTo(max_resolution);
    LOG_IF(FATAL, resolutions.empty())
        << "The maximum supported resolution for " << CodecToString(codec)
        << " is too small: " << max_resolution.first << "x"
        << max_resolution.second;

    // V4L2 API doesn't have a way of querying supported subsamplings and color
    // depth.
    for (const Profile profile : profiles) {
      // TODO(b/172229001, b/188598699): For JPEG profiles, actually, supported
      // subsamplings can be queried by V4L2_CID_JPEG_CHROMA_SUBSAMPLING. But it
      // has never been used in Chrome OS. Call it once we confirm that it works
      // on all V4L2 devices. We temporarily do as if all subsamplings are
      // supported to avoid false negatives.
      // TODO(b/172229001): For other profiles, we should guess them from
      // supported YUV formats of CAPTURE queue for decoding and of OUTPUT queue
      // for encoding.
      std::vector<Subsampling> subsamplings = {Subsampling::kYUV420};
      if (profile == Profile::kJPEG) {
        subsamplings = {Subsampling::kYUV420, Subsampling::kYUV422,
                        Subsampling::kYUV444};
      }

      for (const Subsampling subsampling : subsamplings) {
        const ColorDepth color_depth = profile == Profile::kVP9Profile2
                                           ? ColorDepth::k10bit
                                           : ColorDepth::k8bit;
        for (const Resolution resolution : resolutions) {
          capabilities.push_back(Capability(profile, decode, resolution,
                                            subsampling, color_depth));
        }
      }
    }
  }

  return capabilities;
}

std::vector<Capability> GetCapabilitiesInPaths(
    const std::vector<base::FilePath>& paths, bool decode) {
  std::vector<Capability> capabilities;
  for (const base::FilePath& path : paths) {
    for (auto&& c : GetCapabilitiesInPath(path, decode)) {
      if (!base::Contains(capabilities, c))
        capabilities.push_back(std::move(c));
    }
  }

  return capabilities;
}

std::vector<Capability> GetDecodeCapabilities() {
  const base::FilePath kVideoDecoderDevicePath("/dev/video-dec");
  const base::FilePath kJpegDecoderDevicePath("/dev/jpeg-dec");
  std::vector<base::FilePath> device_paths;
  auto video_decoder_device_paths =
      GetAllFilesWithPrefix(kVideoDecoderDevicePath);
  auto jpeg_decoder_device_paths =
      GetAllFilesWithPrefix(kJpegDecoderDevicePath);
  device_paths.insert(device_paths.end(), video_decoder_device_paths.begin(),
                      video_decoder_device_paths.end());
  device_paths.insert(device_paths.end(), jpeg_decoder_device_paths.begin(),
                      jpeg_decoder_device_paths.end());

  return GetCapabilitiesInPaths(device_paths, /*decode=*/true);
}

std::vector<Capability> GetEncodeCapabilities() {
  const base::FilePath kVideoEncoderDevicePath("/dev/video-enc");
  const base::FilePath kJpegEncoderDevicePath("/dev/jpeg-enc");
  std::vector<base::FilePath> device_paths;
  auto video_encoder_device_paths =
      GetAllFilesWithPrefix(kVideoEncoderDevicePath);
  auto jpeg_encoder_device_paths =
      GetAllFilesWithPrefix(kJpegEncoderDevicePath);
  device_paths.insert(device_paths.end(), video_encoder_device_paths.begin(),
                      video_encoder_device_paths.end());
  device_paths.insert(device_paths.end(), jpeg_encoder_device_paths.begin(),
                      jpeg_encoder_device_paths.end());

  return GetCapabilitiesInPaths(device_paths, /*decode=*/false);
}
}  // namespace

std::vector<Capability> DetectV4L2Capabilities() {
  auto decode_capabilities = GetEncodeCapabilities();
  auto encode_capabilities = GetDecodeCapabilities();

  auto& capabilities = decode_capabilities;
  capabilities.insert(capabilities.end(), encode_capabilities.begin(),
                      encode_capabilities.end());
  return capabilities;
}
