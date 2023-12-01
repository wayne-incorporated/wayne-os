/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "tools/generate_camera_profile.h"

#include <memory>
#include <vector>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <brillo/syslog_logging.h>

#include "cros-camera/constants.h"
#include "cros-camera/utils/camera_config.h"

constexpr char kDestinationDir[] =
    "/mnt/stateful_partition/encrypted/var/cache/camera";
constexpr char kMediaProfileFileName[] = "media_profiles.xml";
constexpr char kMediaProfileDir[] = "/etc/camera";

int GetNumberOfBuiltinCameras() {
  base::FileEnumerator cameras(base::FilePath("/dev"), /*recursive=*/false,
                               base::FileEnumerator::FILES, "camera-internal*");
  int cnt = 0;
  while (!cameras.Next().empty()) {
    cnt++;
  }
  return cnt;
}

cros::Camcorder GetDefaultCamcorder() {
  cros::Camcorder profile;
  profile.file_format = "mp4";
  profile.duration = 60;
  profile.video_codec = "h264";
  profile.video_bitrate = 8000000;
  profile.video_width = 1280;
  profile.video_height = 720;
  profile.video_framerate = 30;
  profile.audio_codec = "aac";
  profile.audio_bitrate = 96000;
  profile.audio_samplerate = 44100;
  profile.audio_channels = 1;
  return profile;
}

std::string GetCamcorderString(int id) {
  cros::Camcorder camcorder = GetDefaultCamcorder();
  std::string quality;
  if (camcorder.video_height >= 2160) {
    quality = "2160p";
  } else if (camcorder.video_height >= 1080) {
    quality = "1080p";
  } else if (camcorder.video_height >= 720) {
    quality = "720p";
  } else if (camcorder.video_height >= 480) {
    quality = "480p";
  }

  std::string str;
  str += base::StringPrintf("    <CamcorderProfiles cameraId=\"%d\">\n", id);
  for (int i = 0; i < 2; i++) {
    std::string quality_str = i ? ("timelapse" + quality) : quality;
    str += base::StringPrintf("        <EncoderProfile quality=\"%s\" ",
                              quality_str.c_str());
    str +=
        base::StringPrintf("fileFormat=\"%s\" duration=\"%d\">\n",
                           camcorder.file_format.c_str(), camcorder.duration);
    str += base::StringPrintf("            <Video codec=\"%s\" bitRate=\"%d\" ",
                              camcorder.video_codec.c_str(),
                              camcorder.video_bitrate);
    str += base::StringPrintf("width=\"%d\" height=\"%d\" frameRate=\"%d\" />",
                              camcorder.video_width, camcorder.video_height,
                              camcorder.video_framerate);
    str += "\n";
    str += base::StringPrintf("            <Audio codec=\"%s\" bitRate=\"%d\" ",
                              camcorder.audio_codec.c_str(),
                              camcorder.audio_bitrate);
    str += base::StringPrintf("sampleRate=\"%d\" channels=\"%d\" />\n",
                              camcorder.audio_samplerate,
                              camcorder.audio_channels);
    str += base::StringPrintf("        </EncoderProfile>\n");
  }
  str += base::StringPrintf("        <ImageEncoding quality=\"90\" />\n");
  str += base::StringPrintf("        <ImageEncoding quality=\"80\" />\n");
  str += base::StringPrintf("        <ImageEncoding quality=\"70\" />\n");
  str += base::StringPrintf("        <ImageDecoding memCap=\"20000000\" />\n");
  str += base::StringPrintf("    </CamcorderProfiles>\n");
  return str;
}

bool GenerateCameraProfile(int num_cameras) {
  const base::FilePath profile =
      base::FilePath(kMediaProfileDir).Append(kMediaProfileFileName);
  std::string content;
  if (!base::ReadFileToString(profile, &content)) {
    LOG(ERROR) << "ReadFileToString fails";
    return false;
  }
  const std::vector<base::StringPiece> lines = base::SplitStringPiece(
      content, "\n", base::WhitespaceHandling::KEEP_WHITESPACE,
      base::SplitResult::SPLIT_WANT_NONEMPTY);

  const base::FilePath generated_profile =
      base::FilePath(kDestinationDir).Append(kMediaProfileFileName);
  if (!base::CreateDirectory(generated_profile.DirName())) {
    LOG(ERROR) << "Create directory failed";
    return false;
  }
  base::File file(generated_profile,
                  base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  CHECK(file.IsValid());

  size_t i;
  for (i = 0; i < lines.size(); i++) {
    file.WriteAtCurrentPos(lines[i].data(), lines[i].length());
    file.WriteAtCurrentPos("\n", 1);
    if (lines[i].find("</CamcorderProfiles>") != base::StringPiece::npos) {
      break;
    }
  }
  // TODO(henryhsu): Write camcorder according to correct value from
  // configuration file instead of using default value.
  for (int id = 1; id < num_cameras; id++) {
    std::string camcorder_string = GetCamcorderString(id);
    file.WriteAtCurrentPos(camcorder_string.c_str(), camcorder_string.length());
  }
  for (i++; i < lines.size(); i++) {
    file.WriteAtCurrentPos(lines[i].data(), lines[i].length());
    file.WriteAtCurrentPos("\n", 1);
  }
  file.Close();
  return true;
}

bool HasCameraFilter() {
  std::unique_ptr<cros::CameraConfig> config = cros::CameraConfig::Create(
      cros::constants::kCrosCameraTestConfigPathString);
  return config->HasKey(cros::constants::kCrosEnableFrontCameraOption) ||
         config->HasKey(cros::constants::kCrosEnableBackCameraOption) ||
         config->HasKey(cros::constants::kCrosEnableExternalCameraOption);
}

int main(int argc, char* argv[]) {
  // Init CommandLine for InitLogging.
  base::CommandLine::Init(argc, argv);
  base::AtExitManager at_exit_manager;
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  if (HasCameraFilter()) {
    // If camera filter flag is presented, autotest toggling camera filter
    // should be responsible for preparing media profile for ARC++.
    LOG(INFO) << "Using camera filter, skip generating media profiles";
    return 0;
  }

  LOG(INFO) << "Starting to generate media profiles";
  int num_builtin_cameras = GetNumberOfBuiltinCameras();

  if (!GenerateCameraProfile(num_builtin_cameras)) {
    LOG(ERROR) << "Generate media profile error";
    return -1;
  }

  return 0;
}
