// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// hw_video_pro_* detectors for detecting HW protected video support by codec
// and encryption scheme. For each detector, check VAAPI capabilities.
// TODO(jkardatzke): Check V4L2 capabilities once we support V4L2 protected
// video.

#if defined(USE_VAAPI)
#include <unistd.h>
#include <va/va.h>
#endif  // defined(USE_VAAPI)

#include "label_detect.h"

#if defined(USE_VAAPI)

static const char* kDRMDevicePattern = "/dev/dri/renderD*";

static const VAConfigAttrib kCencV1CbcVaAttribs[] = {
    {VAConfigAttribEncryption, VA_ENCRYPTION_TYPE_FULLSAMPLE_CBC}};
static const VAConfigAttrib kCencV1CtrVaAttribs[] = {
    {VAConfigAttribEncryption, VA_ENCRYPTION_TYPE_FULLSAMPLE_CTR}};
static const VAConfigAttrib kCencV3CbcVaAttribs[] = {
    {VAConfigAttribEncryption, VA_ENCRYPTION_TYPE_SUBSAMPLE_CBC}};
static const VAConfigAttrib kCencV3CtrVaAttribs[] = {
    {VAConfigAttribEncryption, VA_ENCRYPTION_TYPE_SUBSAMPLE_CTR}};

/* Helper function which detects Widevine protected support for the AES-CTR
 * encryption scheme.
 */
static bool is_widevine_ctr_device(int fd) {
  VAConfigAttrib va_attribs[] = {
      {VAConfigAttribProtectedContentUsage, VA_PC_USAGE_WIDEVINE},
      {VAConfigAttribProtectedContentCipherAlgorithm, VA_PC_CIPHER_AES},
      {VAConfigAttribProtectedContentCipherBlockSize, VA_PC_BLOCK_SIZE_128},
      {VAConfigAttribProtectedContentCipherMode, VA_PC_CIPHER_MODE_CTR}};
  return are_vaapi_attribs_supported(
      fd, VAProfileProtected, VAEntrypointProtectedContent, va_attribs, 4);
}

/* Helper function which detects Widevine protected support for the AES-CBC
 * encryption scheme.
 */
static bool is_widevine_cbc_device(int fd) {
  VAConfigAttrib va_attribs[] = {
      {VAConfigAttribProtectedContentUsage, VA_PC_USAGE_WIDEVINE},
      {VAConfigAttribProtectedContentCipherAlgorithm, VA_PC_CIPHER_AES},
      {VAConfigAttribProtectedContentCipherBlockSize, VA_PC_BLOCK_SIZE_128},
      {VAConfigAttribProtectedContentCipherMode, VA_PC_CIPHER_MODE_CBC}};
  return are_vaapi_attribs_supported(
      fd, VAProfileProtected, VAEntrypointProtectedContent, va_attribs, 4);
}

/* Helper function which returns true if we are running on an AMD platform and
 * it has the kernel driver for protected content. AMD can handle protected
 * content for a codec if it has the tee0 driver and it supports that codec for
 * HW decode.
 */
static bool is_amd_protected_content(int fd) {
  return (access("/dev/tee0", F_OK) == 0) && is_amd_implementation(fd);
}

/* Helper function for detect_video_prot_cencv1_h264_cbc.
 * Determine if given |fd| is a VAAPI device that supports H.264 protected video
 * decoding with CENCv1 CBC encryption.
 */
static bool is_vaapi_prot_h264_cencv1_cbc_device(int fd) {
  if (!is_widevine_cbc_device(fd))
    return false;

  return are_vaapi_attribs_supported(fd, VAProfileH264Main, VAEntrypointVLD,
                                     kCencV1CbcVaAttribs, 1);
}

/* Helper function for detect_video_prot_cencv1_h264_ctr.
 * Determine if given |fd| is a VAAPI device that supports H.264 protected video
 * decoding with CENCv1 CTR encryption.
 */
static bool is_vaapi_prot_h264_cencv1_ctr_device(int fd) {
  if (!is_widevine_ctr_device(fd))
    return false;

  return are_vaapi_attribs_supported(fd, VAProfileH264Main, VAEntrypointVLD,
                                     kCencV1CtrVaAttribs, 1);
}

/* Helper function for detect_video_prot_cencv3_av1_cbc.
 * Determine if given |fd| is a VAAPI device that supports AV1 protected video
 * decoding with CENCv3 CBC encryption.
 */
static bool is_vaapi_prot_av1_cencv3_cbc_device(int fd) {
  if (!is_widevine_cbc_device(fd))
    return false;

  return are_vaapi_attribs_supported(fd, VAProfileAV1Profile0, VAEntrypointVLD,
                                     kCencV3CbcVaAttribs, 1);
}

/* Helper function for detect_video_prot_cencv3_av1_ctr.
 * Determine if given |fd| is a VAAPI device that supports AV1 protected video
 * decoding with CENCv3 CTR encryption.
 */
static bool is_vaapi_prot_av1_cencv3_ctr_device(int fd) {
  if (!is_widevine_ctr_device(fd))
    return false;

  return are_vaapi_attribs_supported(fd, VAProfileAV1Profile0, VAEntrypointVLD,
                                     kCencV3CtrVaAttribs, 1);
}

/* Helper function for detect_video_prot_cencv3_h264_cbc.
 * Determine if given |fd| is a VAAPI device that supports H.264 protected video
 * decoding with CENCv3 CBC encryption.
 */
static bool is_vaapi_prot_h264_cencv3_cbc_device(int fd) {
  if (!is_widevine_cbc_device(fd))
    return false;

  return are_vaapi_attribs_supported(fd, VAProfileH264Main, VAEntrypointVLD,
                                     kCencV3CbcVaAttribs, 1);
}

/* Helper function for detect_video_prot_cencv3_h264_ctr.
 * Determine if given |fd| is a VAAPI device that supports H.264 protected video
 * decoding with CENCv3 CTR encryption.
 */
static bool is_vaapi_prot_h264_cencv3_ctr_device(int fd) {
  if (!is_widevine_ctr_device(fd))
    return false;

  return are_vaapi_attribs_supported(fd, VAProfileH264Main, VAEntrypointVLD,
                                     kCencV3CtrVaAttribs, 1);
}

/* Helper function for detect_video_prot_cencv3_hevc_cbc.
 * Determine if given |fd| is a VAAPI device that supports HEVC protected video
 * decoding with CENCv3 CBC encryption.
 */
static bool is_vaapi_prot_hevc_cencv3_cbc_device(int fd) {
  if (!is_widevine_cbc_device(fd))
    return false;

  return are_vaapi_attribs_supported(fd, VAProfileHEVCMain, VAEntrypointVLD,
                                     kCencV3CbcVaAttribs, 1);
}

/* Helper function for detect_video_prot_cencv3_hevc_ctr.
 * Determine if given |fd| is a VAAPI device that supports HEVC protected video
 * decoding with CENCv3 CTR encryption.
 */
static bool is_vaapi_prot_hevc_cencv3_ctr_device(int fd) {
  if (!is_widevine_ctr_device(fd))
    return false;

  return are_vaapi_attribs_supported(fd, VAProfileHEVCMain, VAEntrypointVLD,
                                     kCencV3CtrVaAttribs, 1);
}

/* Helper function for detect_video_prot_cencv3_vp9_cbc.
 * Determine if given |fd| is a VAAPI device that supports VP9 protected video
 * decoding with CENCv3 CBC encryption.
 */
static bool is_vaapi_prot_vp9_cencv3_cbc_device(int fd) {
  if (!is_widevine_cbc_device(fd))
    return false;

  return are_vaapi_attribs_supported(fd, VAProfileVP9Profile0, VAEntrypointVLD,
                                     kCencV3CbcVaAttribs, 1);
}

/* Helper function for detect_video_prot_cencv3_vp9_ctr.
 * Determine if given |fd| is a VAAPI device that supports VP9 protected video
 * decoding with CENCv3 CTR encryption.
 */
static bool is_vaapi_prot_vp9_cencv3_ctr_device(int fd) {
  if (!is_widevine_ctr_device(fd))
    return false;

  return are_vaapi_attribs_supported(fd, VAProfileVP9Profile0, VAEntrypointVLD,
                                     kCencV3CtrVaAttribs, 1);
}

#endif  // defined(USE_VAAPI)

/* Determines "hw_video_prot_cencv1_h264_cbc" label. That is, the VAAPI device
 * supports decoding of HW protected H.264 video with CENCv1 CBC encryption.
 */
bool detect_video_prot_cencv1_h264_cbc(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_prot_h264_cencv1_cbc_device))
    return true;
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_prot_cencv1_h264_ctr" label. That is, the VAAPI device
 * supports decoding of HW protected H.264 video with CENCv1 CTR encryption.
 */
bool detect_video_prot_cencv1_h264_ctr(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_prot_h264_cencv1_ctr_device))
    return true;
  if (is_any_device(kDRMDevicePattern, is_amd_protected_content) &&
      detect_video_acc_h264()) {
    return true;
  }
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_prot_cencv3_av1_cbc" label. That is, the VAAPI device
 * supports decoding of HW protected AV1 video with CENCv3 CBC encryption.
 */
bool detect_video_prot_cencv3_av1_cbc(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_prot_av1_cencv3_cbc_device))
    return true;
  if (is_any_device(kDRMDevicePattern, is_amd_protected_content) &&
      detect_video_acc_av1()) {
    return true;
  }
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_prot_cencv3_av1_ctr" label. That is, the VAAPI device
 * supports decoding of HW protected AV1 video with CENCv3 CTR encryption.
 */
bool detect_video_prot_cencv3_av1_ctr(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_prot_av1_cencv3_ctr_device))
    return true;
  if (is_any_device(kDRMDevicePattern, is_amd_protected_content) &&
      detect_video_acc_av1()) {
    return true;
  }
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_prot_cencv3_h264_cbc" label. That is, the VAAPI device
 * supports decoding of HW protected H.264 video with CENCv3 CBC encryption.
 */
bool detect_video_prot_cencv3_h264_cbc(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_prot_h264_cencv3_cbc_device))
    return true;
  if (is_any_device(kDRMDevicePattern, is_amd_protected_content) &&
      detect_video_acc_h264()) {
    return true;
  }
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_prot_cencv3_h264_ctr" label. That is, the VAAPI device
 * supports decoding of HW protected H.264 video with CENCv3 CTR encryption.
 */
bool detect_video_prot_cencv3_h264_ctr(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_prot_h264_cencv3_ctr_device))
    return true;
  if (is_any_device(kDRMDevicePattern, is_amd_protected_content) &&
      detect_video_acc_h264()) {
    return true;
  }
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_prot_cencv3_hevc_cbc" label. That is, the VAAPI device
 * supports decoding of HW protected HEVC video with CENCv3 CBC encryption.
 */
bool detect_video_prot_cencv3_hevc_cbc(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_prot_hevc_cencv3_cbc_device))
    return true;
  if (is_any_device(kDRMDevicePattern, is_amd_protected_content) &&
      detect_video_acc_hevc()) {
    return true;
  }
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_prot_cencv3_hevc_ctr" label. That is, the VAAPI device
 * supports decoding of HW protected HEVC video with CENCv3 CTR encryption.
 */
bool detect_video_prot_cencv3_hevc_ctr(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_prot_hevc_cencv3_ctr_device))
    return true;
  if (is_any_device(kDRMDevicePattern, is_amd_protected_content) &&
      detect_video_acc_hevc()) {
    return true;
  }
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_prot_cencv3_vp9_cbc" label. That is, the VAAPI device
 * supports decoding of HW protected VP9 video with CENCv3 CBC encryption.
 */
bool detect_video_prot_cencv3_vp9_cbc(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_prot_vp9_cencv3_cbc_device))
    return true;
  if (is_any_device(kDRMDevicePattern, is_amd_protected_content) &&
      detect_video_acc_vp9()) {
    return true;
  }
#endif  // defined(USE_VAAPI)

  return false;
}

/* Determines "hw_video_prot_cencv3_vp9_ctr" label. That is, the VAAPI device
 * supports decoding of HW protected VP9 video with CENCv3 CTR encryption.
 */
bool detect_video_prot_cencv3_vp9_ctr(void) {
#if defined(USE_VAAPI)
  if (is_any_device(kDRMDevicePattern, is_vaapi_prot_vp9_cencv3_ctr_device))
    return true;
  if (is_any_device(kDRMDevicePattern, is_amd_protected_content) &&
      detect_video_acc_vp9()) {
    return true;
  }
#endif  // defined(USE_VAAPI)

  return false;
}
