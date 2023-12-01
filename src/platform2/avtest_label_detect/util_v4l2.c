// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <linux/videodev2.h>
#include <stdio.h>
#include <string.h>

#include "label_detect.h"

/* Returns whether the device fd supports given format of buffer type.
 * Example of buf_type: V4L2_BUF_TYPE_VIDEO_OUTPUT,
 * V4L2_BUF_TYPE_VIDEO_CAPTURE.
 * */
bool is_v4l2_support_format(int fd,
                            enum v4l2_buf_type buf_type,
                            uint32_t fourcc) {
  int i;
  bool found = false;
  char fourcc_str[5];

  convert_fourcc_to_str(fourcc, fourcc_str);
  TRACE("is_v4l2_support_format(%s)\n", fourcc_str);
  for (i = 0;; ++i) {
    struct v4l2_fmtdesc format_desc;
    memset(&format_desc, 0, sizeof(format_desc));
    format_desc.type = (enum v4l2_buf_type)buf_type;
    format_desc.index = i;
    if (-1 == do_ioctl(fd, VIDIOC_ENUM_FMT, &format_desc)) {
      break;
    }
    convert_fourcc_to_str(format_desc.pixelformat, fourcc_str);
    TRACE("%s supported\n", fourcc_str);
    if (format_desc.pixelformat == fourcc) {
      found = true;
      /* continue the loop in order to output all supported formats */
    }
  }
  TRACE("is_v4l2_support_format: %s\n", found ? "true" : "false");
  return found;
}

/* Returns whether the device fd is V4L2 video encode/decode device. */
bool is_hw_video_acc_device(int fd) {
  struct v4l2_capability cap;
  int ret = do_ioctl(fd, VIDIOC_QUERYCAP, &cap);
  if (ret == 0) {
    if ((cap.capabilities & V4L2_CAP_STREAMING) &&
        (cap.capabilities & V4L2_CAP_VIDEO_M2M_MPLANE)) {
      TRACE("is_hw_video_acc_device: true\n");
      return true;
    }
  }
  TRACE("is_hw_video_acc_device: false\n");
  return false;
}

/* Returns whether the device fd is V4L2 jpeg encode/decode device. */
bool is_hw_jpeg_acc_device(int fd) {
  struct v4l2_capability cap;
  int ret = do_ioctl(fd, VIDIOC_QUERYCAP, &cap);
  if (ret == 0) {
    if ((cap.capabilities & V4L2_CAP_STREAMING) &&
        (cap.capabilities & V4L2_CAP_VIDEO_M2M_MPLANE)) {
      TRACE("is_hw_jpeg_acc_device: true\n");
      return true;
    }
  }
  TRACE("is_hw_jpeg_acc_device: false\n");
  return false;
}

/* Returns success or failure of getting resolution. The maximum resolution is
   returned through arguments. */
bool get_v4l2_max_resolution(int fd,
                             uint32_t fourcc,
                             int32_t* const resolution_width,
                             int32_t* const resolution_height) {
  *resolution_width = 0;
  *resolution_height = 0;

  struct v4l2_frmsizeenum frame_size;
  memset(&frame_size, 0, sizeof(frame_size));
  frame_size.pixel_format = fourcc;

  for (; do_ioctl(fd, VIDIOC_ENUM_FRAMESIZES, &frame_size) == 0;
       ++frame_size.index) {
    if (frame_size.type == V4L2_FRMSIZE_TYPE_DISCRETE) {
      if (frame_size.discrete.width >= *resolution_width &&
          frame_size.discrete.height >= *resolution_height) {
        *resolution_width = frame_size.discrete.width;
        *resolution_height = frame_size.discrete.height;
      }
    } else if (frame_size.type == V4L2_FRMSIZE_TYPE_STEPWISE ||
               frame_size.type == V4L2_FRMSIZE_TYPE_CONTINUOUS) {
      *resolution_width = frame_size.stepwise.max_width;
      *resolution_height = frame_size.stepwise.max_height;
      break;
    }
  }
  return *resolution_width > 0 && *resolution_height > 0;
}

/* Returns whether a v4l2 encoder driver supports variable bitrate (VBR)
 * encoding
 */
bool is_v4l2_enc_vbr_supported(int fd) {
  struct v4l2_queryctrl query_ctrl;
  memset(&query_ctrl, 0, sizeof(query_ctrl));
  query_ctrl.id = V4L2_CID_MPEG_VIDEO_BITRATE_MODE;
  if (do_ioctl(fd, VIDIOC_QUERYCTRL, &query_ctrl)) {
    return false;
  }

  struct v4l2_querymenu query_menu;
  memset(&query_menu, 0, sizeof(query_menu));
  query_menu.id = query_ctrl.id;
  for (query_menu.index = query_ctrl.minimum;
       (int)query_menu.index <= query_ctrl.maximum; query_menu.index++) {
    if (do_ioctl(fd, VIDIOC_QUERYMENU, &query_menu) == 0) {
      if (query_menu.index == V4L2_MPEG_VIDEO_BITRATE_MODE_VBR) {
        return true;
      }
    }
  }

  return false;
}
