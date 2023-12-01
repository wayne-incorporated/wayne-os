// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/gpu/format_util.h"

namespace arc {

video_codec_profile_t ConvertMojoProfileToCodecProfile(
    arc::mojom::VideoCodecProfile profile) {
  switch (profile) {
    case arc::mojom::VideoCodecProfile::H264PROFILE_MIN:
      return H264PROFILE_MIN;
    case arc::mojom::VideoCodecProfile::H264PROFILE_MAIN:
      return H264PROFILE_MAIN;
    case arc::mojom::VideoCodecProfile::H264PROFILE_EXTENDED:
      return H264PROFILE_EXTENDED;
    case arc::mojom::VideoCodecProfile::H264PROFILE_HIGH:
      return H264PROFILE_HIGH;
    case arc::mojom::VideoCodecProfile::H264PROFILE_HIGH10PROFILE:
      return H264PROFILE_HIGH10PROFILE;
    case arc::mojom::VideoCodecProfile::H264PROFILE_HIGH422PROFILE:
      return H264PROFILE_HIGH422PROFILE;
    case arc::mojom::VideoCodecProfile::H264PROFILE_HIGH444PREDICTIVEPROFILE:
      return H264PROFILE_HIGH444PREDICTIVEPROFILE;
    case arc::mojom::VideoCodecProfile::H264PROFILE_SCALABLEBASELINE:
      return H264PROFILE_SCALABLEBASELINE;
    case arc::mojom::VideoCodecProfile::H264PROFILE_SCALABLEHIGH:
      return H264PROFILE_SCALABLEHIGH;
    case arc::mojom::VideoCodecProfile::H264PROFILE_STEREOHIGH:
      return H264PROFILE_STEREOHIGH;
    case arc::mojom::VideoCodecProfile::H264PROFILE_MULTIVIEWHIGH:
      return H264PROFILE_MULTIVIEWHIGH;
    case arc::mojom::VideoCodecProfile::VP8PROFILE_MIN:
      return VP8PROFILE_MIN;
    case arc::mojom::VideoCodecProfile::VP9PROFILE_MIN:
      return VP9PROFILE_MIN;
    case arc::mojom::VideoCodecProfile::VP9PROFILE_PROFILE1:
      return VP9PROFILE_PROFILE1;
    case arc::mojom::VideoCodecProfile::VP9PROFILE_PROFILE2:
      return VP9PROFILE_PROFILE2;
    case arc::mojom::VideoCodecProfile::VP9PROFILE_PROFILE3:
      return VP9PROFILE_PROFILE3;
    case arc::mojom::VideoCodecProfile::HEVCPROFILE_MIN:
      return HEVCPROFILE_MIN;
    case arc::mojom::VideoCodecProfile::HEVCPROFILE_MAIN10:
      return HEVCPROFILE_MAIN10;
    case arc::mojom::VideoCodecProfile::HEVCPROFILE_MAIN_STILL_PICTURE:
      return HEVCPROFILE_MAIN_STILL_PICTURE;
    case arc::mojom::VideoCodecProfile::DOLBYVISION_PROFILE0:
      return DOLBYVISION_PROFILE0;
    case arc::mojom::VideoCodecProfile::DOLBYVISION_PROFILE4:
      return DOLBYVISION_PROFILE4;
    case arc::mojom::VideoCodecProfile::DOLBYVISION_PROFILE5:
      return DOLBYVISION_PROFILE5;
    case arc::mojom::VideoCodecProfile::DOLBYVISION_PROFILE7:
      return DOLBYVISION_PROFILE7;
    case arc::mojom::VideoCodecProfile::THEORAPROFILE_MIN:
      return THEORAPROFILE_MIN;
    case arc::mojom::VideoCodecProfile::AV1PROFILE_PROFILE_MAIN:
      return AV1PROFILE_PROFILE_MAIN;
    case arc::mojom::VideoCodecProfile::AV1PROFILE_PROFILE_HIGH:
      return AV1PROFILE_PROFILE_HIGH;
    case arc::mojom::VideoCodecProfile::AV1PROFILE_PROFILE_PRO:
      return AV1PROFILE_PROFILE_PRO;
    case arc::mojom::VideoCodecProfile::VIDEO_CODEC_PROFILE_UNKNOWN:
    default:
      return VIDEO_CODEC_PROFILE_UNKNOWN;
  }
}

arc::mojom::VideoCodecProfile ConvertCodecProfileToMojoProfile(
    video_codec_profile_t profile) {
  switch (profile) {
    case H264PROFILE_MIN:
      return arc::mojom::VideoCodecProfile::H264PROFILE_MIN;
    case H264PROFILE_MAIN:
      return arc::mojom::VideoCodecProfile::H264PROFILE_MAIN;
    case H264PROFILE_EXTENDED:
      return arc::mojom::VideoCodecProfile::H264PROFILE_EXTENDED;
    case H264PROFILE_HIGH:
      return arc::mojom::VideoCodecProfile::H264PROFILE_HIGH;
    case H264PROFILE_HIGH10PROFILE:
      return arc::mojom::VideoCodecProfile::H264PROFILE_HIGH10PROFILE;
    case H264PROFILE_HIGH422PROFILE:
      return arc::mojom::VideoCodecProfile::H264PROFILE_HIGH422PROFILE;
    case H264PROFILE_HIGH444PREDICTIVEPROFILE:
      return arc::mojom::VideoCodecProfile::
          H264PROFILE_HIGH444PREDICTIVEPROFILE;
    case H264PROFILE_SCALABLEBASELINE:
      return arc::mojom::VideoCodecProfile::H264PROFILE_SCALABLEBASELINE;
    case H264PROFILE_SCALABLEHIGH:
      return arc::mojom::VideoCodecProfile::H264PROFILE_SCALABLEHIGH;
    case H264PROFILE_STEREOHIGH:
      return arc::mojom::VideoCodecProfile::H264PROFILE_STEREOHIGH;
    case H264PROFILE_MULTIVIEWHIGH:
      return arc::mojom::VideoCodecProfile::H264PROFILE_MULTIVIEWHIGH;
    case VP8PROFILE_MIN:
      return arc::mojom::VideoCodecProfile::VP8PROFILE_MIN;
    case VP9PROFILE_MIN:
      return arc::mojom::VideoCodecProfile::VP9PROFILE_MIN;
    case VP9PROFILE_PROFILE1:
      return arc::mojom::VideoCodecProfile::VP9PROFILE_PROFILE1;
    case VP9PROFILE_PROFILE2:
      return arc::mojom::VideoCodecProfile::VP9PROFILE_PROFILE2;
    case VP9PROFILE_PROFILE3:
      return arc::mojom::VideoCodecProfile::VP9PROFILE_PROFILE3;
    case HEVCPROFILE_MIN:
      return arc::mojom::VideoCodecProfile::HEVCPROFILE_MIN;
    case HEVCPROFILE_MAIN10:
      return arc::mojom::VideoCodecProfile::HEVCPROFILE_MAIN10;
    case HEVCPROFILE_MAIN_STILL_PICTURE:
      return arc::mojom::VideoCodecProfile::HEVCPROFILE_MAIN_STILL_PICTURE;
    case DOLBYVISION_PROFILE0:
      return arc::mojom::VideoCodecProfile::DOLBYVISION_PROFILE0;
    case DOLBYVISION_PROFILE4:
      return arc::mojom::VideoCodecProfile::DOLBYVISION_PROFILE4;
    case DOLBYVISION_PROFILE5:
      return arc::mojom::VideoCodecProfile::DOLBYVISION_PROFILE5;
    case DOLBYVISION_PROFILE7:
      return arc::mojom::VideoCodecProfile::DOLBYVISION_PROFILE7;
    case THEORAPROFILE_MIN:
      return arc::mojom::VideoCodecProfile::THEORAPROFILE_MIN;
    case AV1PROFILE_PROFILE_MAIN:
      return arc::mojom::VideoCodecProfile::AV1PROFILE_PROFILE_MAIN;
    case AV1PROFILE_PROFILE_HIGH:
      return arc::mojom::VideoCodecProfile::AV1PROFILE_PROFILE_HIGH;
    case AV1PROFILE_PROFILE_PRO:
      return arc::mojom::VideoCodecProfile::AV1PROFILE_PROFILE_PRO;
    case VIDEO_CODEC_PROFILE_UNKNOWN:
    default:
      return arc::mojom::VideoCodecProfile::VIDEO_CODEC_PROFILE_UNKNOWN;
  }
}

}  // namespace arc
