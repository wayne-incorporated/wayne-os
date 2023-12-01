/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_IMAGE_PROCESSOR_H_
#define CAMERA_HAL_USB_IMAGE_PROCESSOR_H_

#include <memory>
#include <string>

// FourCC pixel formats (defined as V4L2_PIX_FMT_*).
#include <linux/videodev2.h>
// Declarations of HAL_PIXEL_FORMAT_XXX.
#include <system/graphics.h>

#include <base/memory/ptr_util.h>
#include <camera/camera_metadata.h>

#include "hal/usb/frame_buffer.h"

namespace cros {

// V4L2_PIX_FMT_YVU420(YV12) in ImageProcessor has alignment requirement.
// The stride of Y, U, and V planes should a multiple of 16 pixels.
class ImageProcessor {
 public:
  // Calculate the output buffer size when converting to the specified pixel
  // format according to fourcc, width, height, and stride of |frame|.
  // Return 0 on error.
  static size_t GetConvertedSize(FrameBuffer& frame);

  // Convert format from |in_frame.fourcc| to |out_frame->fourcc|. Caller should
  // fill |data|, |buffer_size|, |width|, and |height| of |out_frame|. The
  // function will fill |out_frame->data_size|. Return non-zero error code on
  // failure; return 0 on success.
  int ConvertFormat(FrameBuffer& in_frame, FrameBuffer& out_frame);

  // Scale image size according to |in_frame| and |out_frame|. Only support
  // V4L2_PIX_FMT_YUV420 output format. Caller should fill |data|, |width|,
  // |height|, and |buffer_size| of |out_frame|. The function will fill
  // |data_size| of |out_frame|.
  int Scale(FrameBuffer& in_frame, FrameBuffer& out_frame);

  // Crop and rotate image size according to |in_frame| and |out_frame|. Only
  // support V4L2_PIX_FMT_YUV420 output format. Caller should fill |data|,
  // |width|, |height|, and |buffer_size| of |out_frame|. The function will fill
  // |data_size| of |out_frame|. |rotate_degree| should be 90 or 270.
  int ProcessForInsetPortraitMode(FrameBuffer& in_frame,
                                  FrameBuffer& out_frame,
                                  int rotate_degree);

  // Crop image size according to |in_frame| and |out_frame|. Only
  // support V4L2_PIX_FMT_YUV420 format. Caller should fill |data|, |width|,
  // |height|, and |buffer_size| of |out_frame|. The function will fill
  // |data_size| and |fourcc| of |out_frame|.
  int Crop(FrameBuffer& in_frame, FrameBuffer& out_frame);

 private:
  // Temporary I420 buffer that is used when there is no direct way to convert
  // format F to format F' and need two-steps conversion (F -> I420 -> F').
  std::unique_ptr<SharedFrameBuffer> temp_i420_buffer_;

  // Temporary I420 buffer which is used for gray scale image. That is to say,
  // the U plane and V plane are all filled with 0x80.
  std::unique_ptr<SharedFrameBuffer> temp_i420_buffer_gray_;
};

}  // namespace cros

#endif  // CAMERA_HAL_USB_IMAGE_PROCESSOR_H_
