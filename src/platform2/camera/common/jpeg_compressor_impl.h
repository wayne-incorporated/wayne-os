/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_JPEG_COMPRESSOR_IMPL_H_
#define CAMERA_COMMON_JPEG_COMPRESSOR_IMPL_H_

#include "cros-camera/jpeg_compressor.h"

#include <system/graphics.h>

// We must include cstdio before jpeglib.h. It is a requirement of libjpeg.
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

extern "C" {
#include <jerror.h>
#include <jpeglib.h>
}

#include "cros-camera/camera_metrics.h"

namespace cros {

class JpegEncodeAccelerator;

// Implementation of JpegCompressor. This class is not thread-safe.
class JpegCompressorImpl : public JpegCompressor {
 public:
  explicit JpegCompressorImpl(CameraMojoChannelManagerToken* token);
  ~JpegCompressorImpl() override;

  // To be deprecated.
  bool CompressImage(const void* image,
                     int width,
                     int height,
                     int quality,
                     const void* app1_buffer,
                     uint32_t app1_size,
                     uint32_t out_buffer_size,
                     void* out_buffer,
                     uint32_t* out_data_size,
                     bool enable_hw_encode = true) override;

  bool CompressImageFromHandle(buffer_handle_t input,
                               buffer_handle_t output,
                               int width,
                               int height,
                               int quality,
                               const void* app1_ptr,
                               uint32_t app1_size,
                               uint32_t* out_data_size,
                               bool enable_hw_encode = true) override;

  bool CompressImageFromMemory(void* input,
                               uint32_t input_format,
                               void* output,
                               int output_buffer_size,
                               int width,
                               int height,
                               int quality,
                               const void* app1_ptr,
                               uint32_t app1_size,
                               uint32_t* out_data_size) override;

  // To be deprecated.
  bool GenerateThumbnail(const void* image,
                         int image_width,
                         int image_height,
                         int thumbnail_width,
                         int thumbnail_height,
                         int quality,
                         uint32_t out_buffer_size,
                         void* out_buffer,
                         uint32_t* out_data_size) override;

 private:
  // InitDestination(), EmptyOutputBuffer() and TerminateDestination() are
  // callback functions to be passed into jpeg library.
  static void InitDestination(j_compress_ptr cinfo);
  static boolean EmptyOutputBuffer(j_compress_ptr cinfo);
  static void TerminateDestination(j_compress_ptr cinfo);
  static void OutputErrorMessage(j_common_ptr cinfo);

  // Returns false if errors occur during HW encode.
  bool EncodeHwLegacy(const uint8_t* input_buffer,
                      uint32_t input_buffer_size,
                      int width,
                      int height,
                      const uint8_t* app1_buffer,
                      uint32_t app1_size,
                      uint32_t out_buffer_size,
                      void* out_buffer,
                      uint32_t* out_data_size);

  // Returns false if errors occur.
  bool EncodeLegacy(const void* inYuv,
                    int width,
                    int height,
                    int jpegQuality,
                    const void* app1_buffer,
                    unsigned int app1_size,
                    uint32_t out_buffer_size,
                    void* out_buffer,
                    uint32_t* out_data_size);

  bool EncodeHw(buffer_handle_t input_handle,
                buffer_handle_t output_handle,
                int width,
                int height,
                int jpeg_quality,
                const void* app1_ptr,
                uint32_t app1_size,
                uint32_t* out_data_size);

  bool EncodeSw(const android_ycbcr& input_ycbcr,
                uint32_t input_format,
                void* output_ptr,
                int output_buffer_size,
                int width,
                int height,
                int jpeg_quality,
                const void* app1_ptr,
                unsigned int app1_size,
                uint32_t* out_data_size);

  void SetJpegDestination(jpeg_compress_struct* cinfo);
  void SetJpegCompressStruct(int width,
                             int height,
                             int quality,
                             jpeg_compress_struct* cinfo);
  // Returns false if errors occur.
  bool Compress(jpeg_compress_struct* cinfo, const uint8_t* yuv);

  // Metrics that used to record things like encoding latency.
  std::unique_ptr<CameraMetrics> camera_metrics_;

  std::unique_ptr<cros::JpegEncodeAccelerator> hw_encoder_;
  bool hw_encoder_started_;

  // Process 16 lines of Y and 16 lines of U/V each time.
  // We must pass at least 16 scanlines according to libjpeg documentation.
  static const int kCompressBatchSize = 16;

  // Point to output buffer. JpegCompressorImpl doesn't own this buffer.
  JOCTET* out_buffer_ptr_;

  // Output buffer size.
  uint32_t out_buffer_size_;

  // Final JPEG encoded size.
  uint32_t out_data_size_;

  // Since output buffer is passed from caller, use a variable to indicate
  // buffer is enough to encode or not.
  bool is_encode_success_;

  // Flag to disable SW encode fallback when HW encode failed
  bool force_jpeg_hw_encode_for_testing_;

  // Mojo manager token which is used for Mojo communication.
  CameraMojoChannelManagerToken* mojo_manager_token_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_JPEG_COMPRESSOR_IMPL_H_
