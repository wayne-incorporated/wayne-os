/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_JPEG_COMPRESSOR_H_
#define CAMERA_INCLUDE_CROS_CAMERA_JPEG_COMPRESSOR_H_

#include <cutils/native_handle.h>

#include <memory>

#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "cros-camera/export.h"

namespace cros {

// Interface for YU12 to JPEG compressor.
class CROS_CAMERA_EXPORT JpegCompressor {
 public:
  struct DmaBufPlane {
    int fd;
    int32_t stride;
    uint32_t offset;
    uint32_t size;
  };

  // [Deprecated]
  static std::unique_ptr<JpegCompressor> GetInstance();

  static std::unique_ptr<JpegCompressor> GetInstance(
      CameraMojoChannelManagerToken* token);

  static bool IsSizeSupported(int width, int height);

  virtual ~JpegCompressor() = default;

  // Compresses YU12 image to JPEG format with HW encode acceleration. It would
  // fallback to SW encode if HW encode fails by default.
  // |quality| is the resulted jpeg image quality. It ranges from 1
  // (poorest quality) to 100 (highest quality).
  // |app1_buffer| is the buffer of APP1 segment (exif) which will be added to
  // the compressed image. Caller should pass the size of output buffer to
  // |out_buffer_size|. Encoded result will be written into |output_buffer|.
  // The actually encoded size will be written into |out_data_size| if image
  // encoded successfully. Returns false if errors occur during compression.
  // |enable_hw_encode| controls the HW/SW encode selection strategy.
  // true - Do HW encode first; falls back to SW encode after failing.
  // false - Don't do HW encode; use SW encode directly.
  virtual bool CompressImage(const void* image,
                             int width,
                             int height,
                             int quality,
                             const void* app1_buffer,
                             uint32_t app1_size,
                             uint32_t out_buffer_size,
                             void* out_buffer,
                             uint32_t* out_data_size,
                             bool enable_hw_encode = true) = 0;

  // Compresses YUV image to JPEG format via buffer handles.
  // |quality| is the resulted jpeg image quality. It ranges from 1
  // (poorest quality) to 100 (highest quality).
  // |app1_buffer| is the buffer of APP1 segment (exif) which will be added to
  // the compressed image.
  // For hardware encoding, it encodes |input| to |output| through DMA-buf. If
  // it fallbacks to software encoding, it maps the |input_handle| and
  // |output_handle| to user space. The actually encoded size will be written
  // into |out_data_size| if image encoded successfully. Returns false if errors
  // occur during compression. |enable_hw_encode| controls the HW/SW encode
  // selection strategy.
  // true - Do HW encode first; falls back to SW encode after failing.
  // false - Don't do HW encode; use SW encode directly.
  virtual bool CompressImageFromHandle(buffer_handle_t input,
                                       buffer_handle_t output,
                                       int width,
                                       int height,
                                       int quality,
                                       const void* app1_ptr,
                                       uint32_t app1_size,
                                       uint32_t* out_data_size,
                                       bool enable_hw_encode = true) = 0;

  // Compresses YUV image to JPEG format via pointers to buffer memory.
  // |quality| is the resulted jpeg image quality. It ranges from 1
  // (poorest quality) to 100 (highest quality).
  // |app1_buffer| is the buffer of APP1 segment (exif) which will be added to
  // the compressed image.
  // It is only used for software encoding, which encodes |input| to |output|.
  // The input buffer has format |input_format| and no paddings between image
  // rows and planes. The size of the output JPEG buffer is
  // |output_buffer_size|.
  // The actually encoded size will be written into |out_data_size| if image
  // encoded successfully. Returns false if errors
  // occur during compression.
  virtual bool CompressImageFromMemory(void* input,
                                       uint32_t input_format,
                                       void* output,
                                       int output_buffer_size,
                                       int width,
                                       int height,
                                       int quality,
                                       const void* app1_ptr,
                                       uint32_t app1_size,
                                       uint32_t* out_data_size) = 0;

  // Compresses YU12 image to JPEG format. |quality| is the resulted jpeg
  // image quality. It ranges from 1 (poorest quality) to 100 (highest quality).
  // Caller should pass the size of output buffer to |out_buffer_size|. Encoded
  // result will be written into |output_buffer|. The actually encoded size will
  // be written into |out_data_size| if image encoded successfully. Returns
  // false if errors occur during compression.
  virtual bool GenerateThumbnail(const void* image,
                                 int image_width,
                                 int image_height,
                                 int thumbnail_width,
                                 int thumbnail_height,
                                 int quality,
                                 uint32_t out_buffer_size,
                                 void* out_buffer,
                                 uint32_t* out_data_size) = 0;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_JPEG_COMPRESSOR_H_
