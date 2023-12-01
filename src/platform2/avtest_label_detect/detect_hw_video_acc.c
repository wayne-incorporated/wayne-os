// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// hw_video_acc_* detectors
// For each detector, check both V4L2 and VAAPI capabilities.

#if defined(USE_V4L2_CODEC)
#include <linux/videodev2.h>
#endif  // defined(USE_V4L2_CODEC)

#if defined(USE_VAAPI)
#include <va/va.h>
#endif  // defined(USE_VAAPI)

#include "label_detect.h"

#if defined(USE_V4L2_CODEC)
// TODO(b/255770680): Remove this once V4L2 header is updated.
#ifndef V4L2_PIX_FMT_AV1
#define V4L2_PIX_FMT_AV1 v4l2_fourcc('A', 'V', '0', '1') /* AV1 */
#endif
#ifndef V4L2_PIX_FMT_AV1_FRAME
#define V4L2_PIX_FMT_AV1_FRAME \
  v4l2_fourcc('A', 'V', '1', 'F') /* AV1 parsed frame */
#endif
#endif  // defined(USE_V4L2_CODEC)

#if defined(USE_V4L2_CODEC)
static const char* kJpegDevicePattern = "/dev/jpeg*";
static const char* kVideoDevicePattern = "/dev/video*";

/* Helper function for detect_video_acc_h264.
 * A V4L2 device supports H.264 decoding, if it's
 * a mem-to-mem V4L2 device, i.e. it provides V4L2_CAP_VIDEO_CAPTURE_*,
 * V4L2_CAP_VIDEO_OUTPUT_* and V4L2_CAP_STREAMING capabilities and it supports
 * V4L2_PIX_FMT_H264 as it's input, i.e. for its
 * V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE queue.
 */
static bool is_v4l2_dec_h264_device(int fd) {
  return is_hw_video_acc_device(fd) &&
         (is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                                 V4L2_PIX_FMT_H264) ||
          is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                                 V4L2_PIX_FMT_H264_SLICE));
}

/* Helper function for detect_video_acc_hevc.
 * A V4L2 device supports HEVC decoding, if it's a mem-to-mem V4L2 device,
 * i.e. it provides V4L2_CAP_VIDEO_CAPTURE_*, V4L2_CAP_VIDEO_OUTPUT_* and
 * V4L2_CAP_STREAMING capabilities and it supports V4L2_PIX_FMT_HEVC as it's
 * input, i.e. for its V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE queue.
 */
static bool is_v4l2_dec_hevc_device(int fd) {
  return is_hw_video_acc_device(fd) &&
         (is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                                 V4L2_PIX_FMT_HEVC));
}

/* Helper function for detect_video_acc_vp8.
 * A V4L2 device supports VP8 decoding, if it's a mem-to-mem V4L2 device,
 * i.e. it provides V4L2_CAP_VIDEO_CAPTURE_*, V4L2_CAP_VIDEO_OUTPUT_* and
 * V4L2_CAP_STREAMING capabilities and it supports V4L2_PIX_FMT_VP8 as it's
 * input, i.e. for its V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE queue.
 */
static bool is_v4l2_dec_vp8_device(int fd) {
  return is_hw_video_acc_device(fd) &&
         (is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                                 V4L2_PIX_FMT_VP8) ||
          is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                                 V4L2_PIX_FMT_VP8_FRAME));
}

/* Helper function for detect_video_acc_vp9.
 * A V4L2 device supports VP9 decoding, if it's a mem-to-mem V4L2 device,
 * i.e. it provides V4L2_CAP_VIDEO_CAPTURE_*, V4L2_CAP_VIDEO_OUTPUT_* and
 * V4L2_CAP_STREAMING capabilities and it supports V4L2_PIX_FMT_VP9 as it's
 * input, i.e. for its V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE queue.
 */
static bool is_v4l2_dec_vp9_device(int fd) {
  return is_hw_video_acc_device(fd) &&
         (is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                                 V4L2_PIX_FMT_VP9) ||
          is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                                 V4L2_PIX_FMT_VP9_FRAME));
}

/* Helper function for detect_video_acc_av1.
 * A V4L2 device supports AV1 decoding, if it's a mem-to-mem V4L2 device,
 * i.e. it provides V4L2_CAP_VIDEO_CAPTURE_*, V4L2_CAP_VIDEO_OUTPUT_* and
 * V4L2_CAP_STREAMING capabilities and it supports V4L2_PIX_FMT_AV1 as it's
 * input, i.e. for its V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE queue.
 */
static bool is_v4l2_dec_av1_device(int fd) {
  return is_hw_video_acc_device(fd) &&
         (is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                                 V4L2_PIX_FMT_AV1) ||
          is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                                 V4L2_PIX_FMT_AV1_FRAME));
}

/* Helper function for detect_video_acc_enc_h264.
 * A V4L2 device supports H.264 encoding, if it's a mem-to-mem V4L2 device,
 * i.e. it provides V4L2_CAP_VIDEO_CAPTURE_*, V4L2_CAP_VIDEO_OUTPUT_* and
 * V4L2_CAP_STREAMING capabilities and it supports V4L2_PIX_FMT_H264 as it's
 * output, i.e. for its V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE queue.
 */
static bool is_v4l2_enc_h264_device(int fd) {
  return is_hw_video_acc_device(fd) &&
         is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
                                V4L2_PIX_FMT_H264);
}

/* Helper function for detect_video_acc_enc_h264_vbr.
 * Returns true if the v4l2 device supports h264 encoding (see
 * is_v4l2_enc_h264_device comment) and variable bitrate encoding.
 */
static bool is_v4l2_enc_h264_vbr_device(int fd) {
  return is_v4l2_enc_h264_device(fd) && is_v4l2_enc_vbr_supported(fd);
}

/* Helper function for detect_video_acc_enc_vp8.
 * A V4L2 device supports VP8 encoding, if it's a mem-to-mem V4L2 device,
 * i.e. it provides V4L2_CAP_VIDEO_CAPTURE_*, V4L2_CAP_VIDEO_OUTPUT_* and
 * V4L2_CAP_STREAMING capabilities and it supports V4L2_PIX_FMT_VP8 as it's
 * output, i.e. for its V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE queue.
 */
static bool is_v4l2_enc_vp8_device(int fd) {
  return is_hw_video_acc_device(fd) &&
         is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
                                V4L2_PIX_FMT_VP8);
}

/* Helper function for detect_video_acc_enc_vp8_vbr.
 * Returns true if the v4l2 device supports vp8 encoding (see
 * is_v4l2_enc_vp8_device comment) and variable bitrate encoding.
 */
static bool is_v4l2_enc_vp8_vbr_device(int fd) {
  return is_v4l2_enc_vp8_device(fd) && is_v4l2_enc_vbr_supported(fd);
}

/* Helper function for detect_jpeg_acc_dec.
 * A V4L2 device supports JPEG decoding, if it's a mem-to-mem V4L2 device,
 * i.e. it provides V4L2_CAP_VIDEO_CAPTURE_*, V4L2_CAP_VIDEO_OUTPUT_* and
 * V4L2_CAP_STREAMING capabilities and it supports V4L2_PIX_FMT_JPEG as it's
 * input, i.e. for its V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE queue.
 */
static bool is_v4l2_dec_jpeg_device(int fd) {
  return is_hw_jpeg_acc_device(fd) &&
         is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                                V4L2_PIX_FMT_JPEG);
}

/* Helper function for detect_jpeg_acc_enc.
 * A V4L2 device supports JPEG encoding, if it's a mem-to-mem V4L2 device,
 * i.e. it provides V4L2_CAP_VIDEO_CAPTURE_*, V4L2_CAP_VIDEO_OUTPUT_* and
 * V4L2_CAP_STREAMING capabilities and it supports V4L2_PIX_FMT_JPEG as it's
 * output, i.e. for its V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE queue.
 */
static bool is_v4l2_enc_jpeg_device(int fd) {
  return is_hw_jpeg_acc_device(fd) &&
         is_v4l2_support_format(fd, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
                                V4L2_PIX_FMT_JPEG);
}

#endif  // defined(USE_V4L2_CODEC)

#if defined(USE_VAAPI)

static const char* kDRMDevicePattern = "/dev/dri/renderD*";

/* Helper function for detect_video_acc_h264.
 * Determine given |fd| is a VAAPI device supports H.264 decoding, i.e.
 * it supports one of H.264 profile, has decoding entry point, and output
 * YUV420 formats.
 */
static bool is_vaapi_dec_h264_device(int fd) {
  VAProfile va_profiles[] = {VAProfileH264Baseline, VAProfileH264Main,
                             VAProfileH264High,
                             VAProfileH264ConstrainedBaseline, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointVLD,
                               VA_RT_FORMAT_YUV420)) {
    return true;
  }
  return false;
}

/* Helper function for detect_video_acc_vp8.
 * Dtermine given |fd| is a VAAPI device supports VP8 decoding, i.e. it
 * supports VP8 profile, has decoding entry point, and output YUV420
 * formats.
 */
static bool is_vaapi_dec_vp8_device(int fd) {
#if VA_CHECK_VERSION(0, 35, 0)
  VAProfile va_profiles[] = {VAProfileVP8Version0_3, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointVLD,
                               VA_RT_FORMAT_YUV420)) {
    return true;
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_vp9.
 * Determine given |fd| is a VAAPI device supports VP9 decoding, i.e. it
 * supports VP9 profile 0, has decoding entry point, and can output YUV420
 * format.
 */
static bool is_vaapi_dec_vp9_device(int fd) {
#if VA_CHECK_VERSION(0, 37, 1)
  VAProfile va_profiles[] = {VAProfileVP9Profile0, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointVLD,
                               VA_RT_FORMAT_YUV420)) {
    return true;
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_vp9_2.
 * Determine given |fd| is a VAAPI device supports VP9 decoding Profile 2, i.e.
 * it supports VP9 profile 2, has decoding entry point, and can output YUV420
 * 10BPP format.
 */
static bool is_vaapi_dec_vp9_2_device(int fd) {
#if VA_CHECK_VERSION(0, 38, 1)
  VAProfile va_profiles[] = {VAProfileVP9Profile2, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointVLD,
                               VA_RT_FORMAT_YUV420_10)) {
    return true;
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_av1.
 * Determine if a VAAPI device supports AV1 decoding, i.e. it
 * supports AV1 main profile 0, has decoding entry point, and can output
 * YUV420 format.
 */
static bool is_vaapi_dec_av1_device(int fd) {
#if VA_CHECK_VERSION(1, 8, 0)
  VAProfile va_profiles[] = {VAProfileAV1Profile0, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointVLD,
                               VA_RT_FORMAT_YUV420)) {
    return true;
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_av1_10bpp.
 * Determine if a VAAPI device supports AV1 decoding main
 * profile 0 (10 bit), i.e. it supports AV1 main profile (10 bit),
 * has decoding entry point, and can output YUV420 10BPP format.
 */
static bool is_vaapi_dec_av1_10bpp_device(int fd) {
#if VA_CHECK_VERSION(1, 8, 0)
  VAProfile va_profiles[] = {VAProfileAV1Profile0, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointVLD,
                               VA_RT_FORMAT_YUV420_10)) {
    return true;
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_hevc.
 * Determine if a VAAPI device supports HEVC decoding, i.e. it
 * supports HEVC main profile, has decoding entry point, and can output
 * YUV420 format.
 */
static bool is_vaapi_dec_hevc_device(int fd) {
#if VA_CHECK_VERSION(1, 0, 0)
  VAProfile va_profiles[] = {VAProfileHEVCMain, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointVLD,
                               VA_RT_FORMAT_YUV420)) {
    return true;
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_hevc_10bpp.
 * Determine if a VAAPI device supports HEVC decoding main
 * profile 10 (10 bit), i.e. it supports HEVC main profile 10 (10 bit),
 * has decoding entry point, and can output YUV420 10BPP format.
 */
static bool is_vaapi_dec_hevc_10bpp_device(int fd) {
#if VA_CHECK_VERSION(1, 0, 0)
  VAProfile va_profiles[] = {VAProfileHEVCMain10, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointVLD,
                               VA_RT_FORMAT_YUV420_10)) {
    return true;
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_enc_h264.
 * Determine given |fd| is a VAAPI device supports H.264 encoding, i.e. it
 * support one of H.264 profile, has encoding entry point, and input YUV420
 * formats.
 */
static bool is_vaapi_enc_h264_device(int fd) {
  VAProfile va_profiles[] = {VAProfileH264Baseline, VAProfileH264Main,
                             VAProfileH264High,
                             VAProfileH264ConstrainedBaseline, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointEncSlice,
                               VA_RT_FORMAT_YUV420) ||
      is_vaapi_support_formats(fd, va_profiles, VAEntrypointEncSliceLP,
                               VA_RT_FORMAT_YUV420)) {
    return true;
  }
  return false;
}

/* Helper function for detect_video_acc_enc_h264.
 * Returns true if the vaapi driver supports H.264 encoding (see
 * is_vaapi_enc_h264_device comment) with variable bitrate encoding.
 */
static bool is_vaapi_enc_h264_vbr_device(int fd) {
  VAProfile va_profiles[] = {VAProfileH264Baseline, VAProfileH264Main,
                             VAProfileH264High,
                             VAProfileH264ConstrainedBaseline};
  for (size_t i = 0; i < 4; i++) {
    VAProfile tmp_va_profiles[] = {va_profiles[i], VAProfileNone};
    VAEntrypoint va_entrypoints[] = {VAEntrypointEncSlice,
                                     VAEntrypointEncSliceLP};
    VAConfigAttrib va_attribs[] = {{VAConfigAttribRateControl, VA_RC_VBR}};
    for (size_t j = 0; j < 2; j++) {
      if (is_vaapi_support_formats(fd, tmp_va_profiles, va_entrypoints[j],
                                   VA_RT_FORMAT_YUV420) &&
          are_vaapi_attribs_supported(fd, va_profiles[i], va_entrypoints[j],
                                      va_attribs, 1)) {
        return true;
      }
    }
  }

  return false;
}

/* Helper function for detect_video_acc_enc_vp8.
 * Determine given |fd| is a VAAPI device supports VP8 encoding, i.e. it
 * supports one of VP8 profile, has encoding entry point, and input YUV420
 * formats.
 */
static bool is_vaapi_enc_vp8_device(int fd) {
#if VA_CHECK_VERSION(0, 35, 0)
  VAProfile va_profiles[] = {VAProfileVP8Version0_3, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointEncSlice,
                               VA_RT_FORMAT_YUV420) ||
      is_vaapi_support_formats(fd, va_profiles, VAEntrypointEncSliceLP,
                               VA_RT_FORMAT_YUV420)) {
    return true;
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_enc_vp8.
 * Returns true if the vaapi driver supports VP8 encoding (see
 * is_vaapi_enc_vp8_device comment) with variable bitrate encoding.
 */
static bool is_vaapi_enc_vp8_vbr_device(int fd) {
#if VA_CHECK_VERSION(0, 35, 0)
  VAProfile va_profiles[] = {VAProfileVP8Version0_3, VAProfileNone};
  VAEntrypoint va_entrypoints[] = {VAEntrypointEncSlice,
                                   VAEntrypointEncSliceLP};
  for (int i = 0; i < 2; i++) {
    if (!is_vaapi_support_formats(fd, va_profiles, va_entrypoints[i],
                                  VA_RT_FORMAT_YUV420)) {
      continue;
    }

    VAConfigAttrib va_attribs[] = {{VAConfigAttribRateControl, VA_RC_VBR}};
    if (are_vaapi_attribs_supported(fd, VAProfileVP8Version0_3,
                                    va_entrypoints[i], va_attribs, 1)) {
      return true;
    }
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_enc_vp9.
 * Determine given |fd| is a VAAPI device supports VP9 encoding, i.e. it
 * supports one of VP9 profile, has encoding entry point, and input YUV420
 * formats.
 */
static bool is_vaapi_enc_vp9_device(int fd) {
#if VA_CHECK_VERSION(0, 37, 1)
  VAProfile va_profiles[] = {VAProfileVP9Profile0, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointEncSlice,
                               VA_RT_FORMAT_YUV420) ||
      is_vaapi_support_formats(fd, va_profiles, VAEntrypointEncSliceLP,
                               VA_RT_FORMAT_YUV420)) {
    return true;
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_enc_vp9.
 * Returns true if the vaapi driver supports VP9 encoding (see
 * is_vaapi_enc_vp9_device comment) with variable bitrate encoding.
 */
static bool is_vaapi_enc_vp9_vbr_device(int fd) {
#if VA_CHECK_VERSION(0, 37, 1)
  VAProfile va_profiles[] = {VAProfileVP9Profile0, VAProfileNone};
  VAEntrypoint va_entrypoints[] = {VAEntrypointEncSlice,
                                   VAEntrypointEncSliceLP};
  for (int i = 0; i < 2; i++) {
    if (!is_vaapi_support_formats(fd, va_profiles, va_entrypoints[i],
                                  VA_RT_FORMAT_YUV420)) {
      continue;
    }

    VAConfigAttrib va_attribs[] = {{VAConfigAttribRateControl, VA_RC_VBR}};
    if (are_vaapi_attribs_supported(fd, VAProfileVP9Profile0, va_entrypoints[i],
                                    va_attribs, 1)) {
      return true;
    }
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_enc_av1.
 * Determine if a VAAPI device supports AV1 encoding.
 */
static bool is_vaapi_enc_av1_vbr_device(int fd) {
#if VA_CHECK_VERSION(1, 17, 0)
  VAProfile va_profiles[] = {VAProfileAV1Profile0, VAProfileNone};
  VAConfigAttrib va_attribs[] = {{VAConfigAttribRateControl, VA_RC_VBR}};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointEncSliceLP,
                               VA_RT_FORMAT_YUV420) &&
      are_vaapi_attribs_supported(fd, VAProfileAV1Profile0,
                                  VAEntrypointEncSliceLP, va_attribs, 1)) {
    return true;
  }
#endif
  return false;
}

/* Helper function for detect_video_acc_enc_av1.
 * Determine if a VAAPI device supports AV1 encoding.
 */
static bool is_vaapi_enc_av1_device(int fd) {
#if VA_CHECK_VERSION(1, 17, 0)
  VAProfile va_profiles[] = {VAProfileAV1Profile0, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointEncSliceLP,
                               VA_RT_FORMAT_YUV420)) {
    return true;
  }
#endif
  return false;
}

/* Helper function for detect_jpeg_acc_dec.
 * Determine given |fd| is a VAAPI device supports JPEG decoding, i.e. it
 * supports JPEG profile, has decoding entry point, and output YUV420
 * formats.
 */
static bool is_vaapi_dec_jpeg_device(int fd) {
  VAProfile va_profiles[] = {VAProfileJPEGBaseline, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointVLD,
                               VA_RT_FORMAT_YUV420)) {
    return true;
  }
  return false;
}

/* Helper function for detect_jpeg_acc_enc.
 * Determine given |fd| is a VAAPI device supports JPEG encoding, i.e. it
 * supports JPEG profile, has encoding entry point, and accepts YUV420
 * as input.
 */
static bool is_vaapi_enc_jpeg_device(int fd) {
  VAProfile va_profiles[] = {VAProfileJPEGBaseline, VAProfileNone};
  if (is_vaapi_support_formats(fd, va_profiles, VAEntrypointEncPicture,
                               VA_RT_FORMAT_YUV420)) {
    return true;
  }
  return false;
}

#endif  // defined(USE_VAAPI)

/* Determines "hw_video_acc_h264" label. That is, either the VAAPI device
 * supports one of H.264 profile, has decoding entry point, and output
 * YUV420 formats. Or there is a /dev/video* device supporting H.264
 * decoding.
 */
bool detect_video_acc_h264(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_dec_h264_device))
    return true;
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_dec_h264_device))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "hw_video_acc_vp8" label. That is, either the VAAPI device
 * supports VP8 profile, has decoding entry point, and output YUV420
 * formats. Or there is a /dev/video* device supporting VP8 decoding.
 */
bool detect_video_acc_vp8(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_dec_vp8_device))
    return true;
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_dec_vp8_device))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "hw_video_acc_vp9" label. That is, either the VAAPI device
 * supports VP9 profile, has decoding entry point, and output YUV420
 * formats. Or there is a /dev/video* device supporting VP9 decoding.
 */
bool detect_video_acc_vp9(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_dec_vp9_device))
    return true;
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_dec_vp9_device))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "hw_video_acc_vp9_2" label. That is, either the VAAPI device
 * supports VP9 profile 2, has decoding entry point, and output YUV420 10BPP
 * format.
 */
bool detect_video_acc_vp9_2(void) {
#if defined(USE_VAAPI)
  return is_any_device(kDRMDevicePattern, is_vaapi_dec_vp9_2_device);
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_acc_av1" label. That is, either the VAAPI device
 * supports AV1 main profile 0, has decoding entry point, and output YUV420
 * formats.
 */
bool detect_video_acc_av1(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_dec_av1_device))
    return true;
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_dec_av1_device))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "hw_video_acc_av1_10bpp" label. That is, either the VAAPI device
 * supports AV1 main profile 0 (10bit), has decoding entry point, and output
 * YUV420 10BPP formats.
 */
bool detect_video_acc_av1_10bpp(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_dec_av1_10bpp_device))
    return true;
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_acc_hevc" label. That is, the VAAPI device supports HEVC
 * main profile, has decoding entry point, and outputs YUV420 format.
 */
bool detect_video_acc_hevc(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_dec_hevc_device))
    return true;
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_dec_hevc_device))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "hw_video_acc_hevc_10bpp" label. That is, the VAAPI device
 * supports HEVC main profile 10 (10bit), has decoding entry point, and outputs
 * YUV420 10BPP format.
 */
bool detect_video_acc_hevc_10bpp(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_dec_hevc_10bpp_device))
    return true;
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_acc_enc_h264" label. That is, either the VAAPI
 * device supports one of H.264 profile, has encoding entry point, and
 * input YUV420 formats. Or there is a /dev/video* device supporting H.264
 * encoding.
 */
bool detect_video_acc_enc_h264(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_enc_h264_device))
    return true;
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_enc_h264_device))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "hw_video_acc_enc_h264_vbr" label. That is, either there is a
 * VAAPI device that supports an H.264 profile with an encoding entrypoint for
 * YUV420 and variable bitrate encoding, or there is a /dev/video* device that
 * supports H.264 encoding and variable bitrate encoding.
 */
bool detect_video_acc_enc_h264_vbr(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_enc_h264_vbr_device))
    return true;
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_enc_h264_vbr_device))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "hw_video_acc_enc_vp8" label. That is, either the VAAPI device
 * supports one of VP8 profile, has encoding entry point, and input YUV420
 * formats. Or there is a /dev/video* device supporting VP8 encoding.
 */
bool detect_video_acc_enc_vp8(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_enc_vp8_device))
    return true;
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_enc_vp8_device))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "hw_video_acc_enc_vp8_vbr" label. That is, either there is a VAAPI
 * device that supports a VP8 profile with an encoding entrypoint for YUV420 and
 * variable bitrate encoding, or there is a /dev/video* device that supports VP8
 * encoding and variable bitrate encoding.
 */
bool detect_video_acc_enc_vp8_vbr(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_enc_vp8_vbr_device))
    return true;
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_enc_vp8_vbr_device))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "hw_video_acc_enc_vp9" label. That is, either the VAAPI device
 * supports one of VP9 profile, has encoding entry point, and input YUV420
 * formats.
 */
bool detect_video_acc_enc_vp9(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_enc_vp9_device))
    return true;
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_acc_enc_vp9_vbr" label. That is, there is a VAAPI device
 * that supports a VP9 profile with an encoding entrypoint for YUV420 and
 * variable bitrate encoding.
 */
bool detect_video_acc_enc_vp9_vbr(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_enc_vp9_vbr_device))
    return true;
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_acc_enc_av1" label. That is, there is a VAAPI device
 * that supports a AV1 profile with an encoding entrypoint and input YUV420
 * formats.
 */
bool detect_video_acc_enc_av1(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_enc_av1_device))
    return true;
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_acc_enc_av1_vbr" label. That is, there is a VAAPI device
 * that supports a AV1 profile with an encoding entrypoint and input YUV420
 * formats.
 */
bool detect_video_acc_enc_av1_vbr(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_enc_av1_vbr_device))
    return true;
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_jpeg_acc_dec" label. That is, either the VAAPI device
 * supports jpeg profile, has decoding entry point, and output YUV420
 * formats. Or there is a /dev/jpeg* device supporting JPEG decoding.
 */
bool detect_jpeg_acc_dec(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_dec_jpeg_device))
    return true;
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kJpegDevicePattern, is_v4l2_dec_jpeg_device))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "hw_jpeg_acc_enc" label. That is, either the VAAPI device
 * supports jpeg profile, has encoding entry point, and output JPEG
 * formats. Or there is a /dev/jpeg* device supporting JPEG encoding.
 */
bool detect_jpeg_acc_enc(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_enc_jpeg_device))
    return true;
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kJpegDevicePattern, is_v4l2_enc_jpeg_device))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}
