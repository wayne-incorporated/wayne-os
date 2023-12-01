// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef AVTEST_LABEL_DETECT_LABEL_DETECT_H_
#define AVTEST_LABEL_DETECT_LABEL_DETECT_H_

#include <stdbool.h>
#include <stdint.h>

#if defined(USE_V4L2_CODEC)
#include <linux/videodev2.h>
#endif  // defined(USE_V4L2_CODEC)

#if defined(USE_VAAPI)
#include <va/va.h>
#endif  // defined (USE_VAAPI)

/* main.c */
extern int verbose;
#define TRACE(...)         \
  do {                     \
    if (verbose)           \
      printf(__VA_ARGS__); \
  } while (0)

/* table_lookup.c */
extern void detect_label_by_board_name(void);

/* util.c */
extern int do_ioctl(int fd, int request, void* arg);
extern bool is_any_device(const char* pattern, bool (*func)(int fd));
extern bool does_any_device_support_resolution(const char* pattern,
                                               bool (*func)(int fd,
                                                            int min_width,
                                                            int min_height),
                                               int32_t min_width,
                                               int32_t min_height);
extern void convert_fourcc_to_str(uint32_t fourcc, char* str);

/* util_v4l2 */
#if defined(USE_V4L2_CODEC)
extern bool is_v4l2_support_format(int fd,
                                   enum v4l2_buf_type buf_type,
                                   uint32_t fourcc);
extern bool is_hw_video_acc_device(int fd);
extern bool is_hw_jpeg_acc_device(int fd);
bool get_v4l2_max_resolution(int fd,
                             uint32_t fourcc,
                             int32_t* const resolution_width,
                             int32_t* const resolution_height);
bool is_v4l2_enc_vbr_supported(int fd);
#endif  // defined(USE_V4L2_CODEC)

/* util_vaapi */
#if defined(USE_VAAPI)
bool is_vaapi_support_formats(int fd,
                              const VAProfile* profiles,
                              VAEntrypoint entrypoint,
                              unsigned int format);
bool get_vaapi_max_resolution(int fd,
                              const VAProfile* profiles,
                              VAEntrypoint entrypoint,
                              unsigned int format,
                              int32_t* const resolution_width,
                              int32_t* const resolution_height);
bool are_vaapi_attribs_supported(int fd,
                                 VAProfile va_profile,
                                 VAEntrypoint entrypoint,
                                 const VAConfigAttrib* required_attribs,
                                 int num_required_attribs);
bool is_amd_implementation(int fd);
#endif  // defined(USE_VAAPI)

/* detectors */
extern bool detect_video_acc_h264(void);
extern bool detect_video_acc_vp8(void);
extern bool detect_video_acc_vp9(void);
extern bool detect_video_acc_vp9_2(void);
extern bool detect_video_acc_av1(void);
extern bool detect_video_acc_av1_10bpp(void);
extern bool detect_video_acc_hevc(void);
extern bool detect_video_acc_hevc_10bpp(void);
extern bool detect_video_acc_enc_h264(void);
extern bool detect_video_acc_enc_h264_vbr(void);
extern bool detect_video_acc_enc_vp8(void);
extern bool detect_video_acc_enc_vp8_vbr(void);
extern bool detect_video_acc_enc_vp9(void);
extern bool detect_video_acc_enc_vp9_vbr(void);
extern bool detect_video_acc_enc_av1(void);
extern bool detect_video_acc_enc_av1_vbr(void);
extern bool detect_jpeg_acc_dec(void);
extern bool detect_jpeg_acc_enc(void);
bool detect_4k_device_h264(void);
bool detect_4k_device_vp8(void);
bool detect_4k_device_vp9(void);
bool detect_4k_device_av1(void);
bool detect_4k_device_av1_10bpp(void);
bool detect_4k_device_hevc(void);
bool detect_4k_device_hevc_10bpp(void);
bool detect_8k_device_h264(void);
bool detect_8k_device_vp9(void);
bool detect_8k_device_av1(void);
bool detect_8k_device_av1_10bpp(void);
bool detect_8k_device_hevc(void);
bool detect_8k_device_hevc_10bpp(void);
bool detect_4k_device_enc_h264(void);
bool detect_4k_device_enc_vp8(void);
bool detect_4k_device_enc_vp9(void);
bool detect_4k_device_enc_av1(void);
bool detect_video_prot_cencv1_h264_cbc(void);
bool detect_video_prot_cencv1_h264_ctr(void);
bool detect_video_prot_cencv3_av1_cbc(void);
bool detect_video_prot_cencv3_av1_ctr(void);
bool detect_video_prot_cencv3_h264_cbc(void);
bool detect_video_prot_cencv3_h264_ctr(void);
bool detect_video_prot_cencv3_hevc_cbc(void);
bool detect_video_prot_cencv3_hevc_ctr(void);
bool detect_video_prot_cencv3_vp9_cbc(void);
bool detect_video_prot_cencv3_vp9_ctr(void);
#endif  // AVTEST_LABEL_DETECT_LABEL_DETECT_H_
