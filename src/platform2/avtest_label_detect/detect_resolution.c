// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// resolution detectors

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

#if defined(USE_VAAPI) || defined(USE_V4L2_CODEC)
static const int32_t width_4k = 3840;
static const int32_t height_4k = 2160;
#endif
#if defined(USE_VAAPI)
static const int32_t width_8k = 7680;
static const int32_t height_8k = 4320;
#endif

#if defined(USE_VAAPI)
#if VA_CHECK_VERSION(0, 35, 0)

static const char kDRMDevicePattern[] = "/dev/dri/renderD*";

static const VAProfile va_profiles_h264[] = {
    VAProfileH264Baseline, VAProfileH264Main, VAProfileH264High,
    VAProfileH264ConstrainedBaseline, VAProfileNone};

static const VAProfile va_profiles_vp8[] = {VAProfileVP8Version0_3,
                                            VAProfileNone};

static const VAProfile va_profiles_vp9[] = {VAProfileVP9Profile0,
                                            VAProfileNone};

static const VAProfile va_profiles_av1[] = {VAProfileAV1Profile0,
                                            VAProfileNone};

static const VAProfile va_profiles_hevc[] = {VAProfileHEVCMain, VAProfileNone};

static const VAProfile va_profiles_hevc_10bpp[] = {VAProfileHEVCMain10,
                                                   VAProfileNone};

/* Determines if a VAAPI device associated with given |fd| supports
 * |va_profiles| for |va_entrypoint|, and its maximum resolution is larger
 * than or equal to |min_width|x|min_height|.
 */
static bool query_support_for(int fd,
                              const VAProfile* va_profiles,
                              VAEntrypoint va_entrypoint,
                              bool is_10bpp,
                              int32_t min_width,
                              int32_t min_height) {
  int32_t resolution_width = 0;
  int32_t resolution_height = 0;
  const unsigned int va_format =
      is_10bpp ? VA_RT_FORMAT_YUV420_10 : VA_RT_FORMAT_YUV420;

  return is_vaapi_support_formats(fd, va_profiles, va_entrypoint, va_format) &&
         get_vaapi_max_resolution(fd, va_profiles, va_entrypoint, va_format,
                                  &resolution_width, &resolution_height) &&
         resolution_width >= min_width && resolution_height >= min_height;
}

static bool query_support_for_dec_h264(int fd,
                                       int32_t min_width,
                                       int32_t min_height) {
  return query_support_for(fd, va_profiles_h264, VAEntrypointVLD, false,
                           min_width, min_height);
}

static bool query_support_for_enc_h264(int fd,
                                       int32_t min_width,
                                       int32_t min_height) {
  return query_support_for(fd, va_profiles_h264, VAEntrypointEncSlice, false,
                           min_width, min_height) ||
         query_support_for(fd, va_profiles_h264, VAEntrypointEncSliceLP, false,
                           min_width, min_height);
}

static bool query_support_for_dec_vp8(int fd,
                                      int32_t min_width,
                                      int32_t min_height) {
  return query_support_for(fd, va_profiles_vp8, VAEntrypointVLD, false,
                           min_width, min_height);
}

static bool query_support_for_enc_vp8(int fd,
                                      int32_t min_width,
                                      int32_t min_height) {
  return query_support_for(fd, va_profiles_vp8, VAEntrypointEncSlice, false,
                           min_width, min_height) ||
         query_support_for(fd, va_profiles_vp8, VAEntrypointEncSliceLP, false,
                           min_width, min_height);
}

static bool query_support_for_dec_vp9(int fd,
                                      int32_t min_width,
                                      int32_t min_height) {
  return query_support_for(fd, va_profiles_vp9, VAEntrypointVLD, false,
                           min_width, min_height);
}

static bool query_support_for_enc_vp9(int fd,
                                      int32_t min_width,
                                      int32_t min_height) {
  return query_support_for(fd, va_profiles_vp9, VAEntrypointEncSlice, false,
                           min_width, min_height) ||
         query_support_for(fd, va_profiles_vp9, VAEntrypointEncSliceLP, false,
                           min_width, min_height);
}

static bool query_support_for_enc_av1(int fd,
                                      int32_t min_width,
                                      int32_t min_height) {
  return query_support_for(fd, va_profiles_av1, VAEntrypointEncSliceLP, false,
                           min_width, min_height);
}

static bool query_support_for_dec_av1(int fd,
                                      int32_t min_width,
                                      int32_t min_height) {
  return query_support_for(fd, va_profiles_av1, VAEntrypointVLD, false,
                           min_width, min_height);
}

static bool query_support_for_dec_av1_10bpp(int fd,
                                            int32_t min_width,
                                            int32_t min_height) {
  return query_support_for(fd, va_profiles_av1, VAEntrypointVLD, true,
                           min_width, min_height);
}

static bool query_support_for_dec_hevc(int fd,
                                       int32_t min_width,
                                       int32_t min_height) {
  return query_support_for(fd, va_profiles_hevc, VAEntrypointVLD, false,
                           min_width, min_height);
}

static bool query_support_for_dec_hevc_10bpp(int fd,
                                             int32_t min_width,
                                             int32_t min_height) {
  return query_support_for(fd, va_profiles_hevc_10bpp, VAEntrypointVLD, true,
                           min_width, min_height);
}

#endif  // VA_CHECK_VERSION(0, 38, 1)
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)

static const char kVideoDevicePattern[] = "/dev/video*";

/* Determined if a V4L2 device associated with given |fd| supports |pix_fmt|
 * for |buf_type|, and its maximum resolution is larger than 3840x2160.
 */
static bool is_v4l2_4k_device(int fd,
                              enum v4l2_buf_type buf_type,
                              uint32_t pix_fmt) {
  int32_t resolution_width;
  int32_t resolution_height;
  if (!is_hw_video_acc_device(fd)) {
    return false;
  }
  if (is_v4l2_support_format(fd, buf_type, pix_fmt)) {
    if (get_v4l2_max_resolution(fd, pix_fmt, &resolution_width,
                                &resolution_height)) {
      return resolution_width >= width_4k && resolution_height >= height_4k;
    }
  }
  return false;
}

// Determines if is_v4l2_4k_device() for H264 decoding.
static bool is_v4l2_4k_device_dec_h264(int fd) {
  return is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                           V4L2_PIX_FMT_H264) ||
         is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                           V4L2_PIX_FMT_H264_SLICE);
}

// Determines if is_v4l2_4k_device() for H264 encoding.
static bool is_v4l2_4k_device_enc_h264(int fd) {
  return is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
                           V4L2_PIX_FMT_H264);
}

// Determines if is_v4l2_4k_device() for VP8 decoding.
static bool is_v4l2_4k_device_dec_vp8(int fd) {
  return is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                           V4L2_PIX_FMT_VP8) ||
         is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                           V4L2_PIX_FMT_VP8_FRAME);
}

// Determines if is_v4l2_4k_device() for VP8 encoding.
static bool is_v4l2_4k_device_enc_vp8(int fd) {
  return is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
                           V4L2_PIX_FMT_VP8);
}

// Determines if is_v4l2_4k_device() for VP9 decoding.
static bool is_v4l2_4k_device_dec_vp9(int fd) {
  return is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                           V4L2_PIX_FMT_VP9) ||
         is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                           V4L2_PIX_FMT_VP9_FRAME);
}

// Determines if is_v4l2_4k_device() for VP9 encoding.
static bool is_v4l2_4k_device_enc_vp9(int fd) {
  return is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
                           V4L2_PIX_FMT_VP9);
}

// Determines if is_v4l2_4k_device() for HEVC decoding.
static bool is_v4l2_4k_device_dec_hevc(int fd) {
  return is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                           V4L2_PIX_FMT_HEVC);
}

// Determines if is_v4l2_4k_device() for AV1 decoding.
static bool is_v4l2_4k_device_dec_av1(int fd) {
  return is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                           V4L2_PIX_FMT_AV1) ||
         is_v4l2_4k_device(fd, V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                           V4L2_PIX_FMT_AV1_FRAME);
}

#endif  // defined(USE_V4L2_CODEC)

/* Determines "4k_video_h264". Return true, if either the VAAPI device
 * supports 4k resolution H264 decoding, has decoding entry point,
 * and input YUV420 formats. Or there is a
 * /dev/video* device supporting 4k resolution H264 decoding.
 */
bool detect_4k_device_h264(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_h264, width_4k, height_4k);
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_4k_device_dec_h264))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "4k_video_vp8". Return true, if either the VAAPI device
 * supports 4k resolution VP8 decoding, has decoding entry point,
 * and input YUV420 formats. Or there is a
 * /dev/video* device supporting 4k resolution VP8 decoding.
 */
bool detect_4k_device_vp8(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_vp8, width_4k, height_4k);
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_4k_device_dec_vp8))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "4k_video_vp9". Return true, if either the VAAPI device
 * supports 4k resolution VP9 decoding, has decoding entry point,
 * and input YUV420 formats. Or there is a
 * /dev/video* device supporting 4k resolution VP9 decoding.
 */
bool detect_4k_device_vp9(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_vp9, width_4k, height_4k);
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_4k_device_dec_vp9))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "4k_video_av1". Return true, if either the VAAPI device
 * supports 4k resolution AV1 decoding, has decoding entry point,
 * and input YUV420 formats.
 */
bool detect_4k_device_av1(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_av1, width_4k, height_4k);
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_4k_device_dec_av1))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "4k_video_av1_10bpp". Return true, if either the VAAPI device
 * supports 4k resolution AV1 10BPP decoding, has decoding entry point,
 * and input YUV420 formats.
 */
bool detect_4k_device_av1_10bpp(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_av1_10bpp, width_4k, height_4k);
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "4k_video_hevc". Return true, if the VAAPI device supports 4k
 * resolution HEVC main decoding, has decoding entry point, and outputs YUV420
 * format.
 */
bool detect_4k_device_hevc(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_hevc, width_4k, height_4k);
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_4k_device_dec_hevc))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "4k_video_hevc_10bpp". Return true, if the VAAPI device supports
 * 4k resolution HEVC main10 10BPP decoding, has decoding entry point, and
 * outputs YUV420 format.
 */
bool detect_4k_device_hevc_10bpp(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_hevc_10bpp, width_4k, height_4k);
#endif  // defined(USE_VAAPI)

  return false;
}

bool detect_8k_device_h264(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_h264, width_8k, height_8k);
#endif  // defined(USE_VAAPI)

  return false;
}

bool detect_8k_device_vp9(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_vp9, width_8k, height_8k);
#endif  // defined(USE_VAAPI)

  return false;
}

bool detect_8k_device_av1(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_av1, width_8k, height_8k);
#endif  // defined(USE_VAAPI)

  return false;
}

bool detect_8k_device_av1_10bpp(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_av1_10bpp, width_8k, height_8k);
#endif  // defined(USE_VAAPI)

  return false;
}

bool detect_8k_device_hevc(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_hevc, width_8k, height_8k);
#endif  // defined(USE_VAAPI)

  return false;
}

bool detect_8k_device_hevc_10bpp(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_dec_hevc_10bpp, width_8k, height_8k);
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "4k_video_enc_h264". Return true, if either the VAAPI device
 * supports 4k resolution H264 encoding, has encoding entry point,
 * and input YUV420 formats. Or there is a
 * /dev/video* device supporting 4k resolution H264 encoding.
 */
bool detect_4k_device_enc_h264(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_enc_h264, width_4k, height_4k);
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_4k_device_enc_h264))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "4k_video_enc_vp8". Return true, if either the VAAPI device
 * supports 4k resolution VP8 encoding, has encoding entry point,
 * and input YUV420 formats. Or there is a
 * /dev/video* device supporting 4k resolution VP8 encoding.
 */
bool detect_4k_device_enc_vp8(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_enc_vp8, width_4k, height_4k);
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_4k_device_enc_vp8))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "4k_video_enc_vp9". Return true, if either the VAAPI device
 * supports 4k resolution VP9 encoding, has encoding entry point,
 * and input YUV420 formats. Or there is a
 * /dev/video* device supporting 4k resolution VP9 encoding.
 */
bool detect_4k_device_enc_vp9(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_enc_vp9, width_4k, height_4k);
#endif  // defined(USE_VAAPI)

#if defined(USE_V4L2_CODEC)
  if (is_any_device(kVideoDevicePattern, is_v4l2_4k_device_enc_vp9))
    return true;
#endif  // defined(USE_V4L2_CODEC)

  return false;
}

/* Determines "4k_video_enc_av1". Return true, if the VAAPI device
 * supports 4k resolution AV1 encoding, has encoding entry point,
 * and input YUV420 formats.
 */
bool detect_4k_device_enc_av1(void) {
#if defined(USE_VAAPI)
  return does_any_device_support_resolution(
      kDRMDevicePattern, query_support_for_enc_av1, width_4k, height_4k);
#endif  // defined(USE_VAAPI)

  return false;
}
