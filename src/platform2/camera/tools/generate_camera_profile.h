/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_TOOLS_GENERATE_CAMERA_PROFILE_H_
#define CAMERA_TOOLS_GENERATE_CAMERA_PROFILE_H_

#include <string>

namespace cros {

struct Camcorder {
  std::string file_format;
  int32_t duration;

  std::string video_codec;
  int32_t video_bitrate;
  int32_t video_width;
  int32_t video_height;
  int32_t video_framerate;

  std::string audio_codec;
  int32_t audio_bitrate;
  int32_t audio_samplerate;
  int32_t audio_channels;
};

}  // namespace cros

#endif  // CAMERA_TOOLS_GENERATE_CAMERA_PROFILE_H_
