/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/jpeg_compressor_impl.h"

#include <memory>
#include <utility>

#include <errno.h>
#include <libyuv.h>
#include <linux/videodev2.h>
#include <time.h>

#include <base/check.h>
#include <base/memory/ptr_util.h>
#include <base/memory/writable_shared_memory_region.h>
#include <base/timer/elapsed_timer.h>
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_mojo_channel_manager.h"
#include "cros-camera/common.h"
#include "cros-camera/jpeg_encode_accelerator.h"
#include "cros-camera/utils/camera_config.h"

namespace cros {

// JPEG format uses 2 bytes to denote the size of a segment, and the size
// includes the 2 bytes used for specifying it. Therefore, maximum data size
// allowed is: 65535 - 2 = 65533.
constexpr size_t kMaxMarkerSizeAllowed = 65533;

// The destination manager that can access members in JpegCompressorImpl.
struct destination_mgr {
 public:
  struct jpeg_destination_mgr mgr;
  JpegCompressorImpl* compressor;
};

// static
std::unique_ptr<JpegCompressor> JpegCompressor::GetInstance() {
  return JpegCompressor::GetInstance(CameraMojoChannelManager::GetInstance());
}

// static
std::unique_ptr<JpegCompressor> JpegCompressor::GetInstance(
    CameraMojoChannelManagerToken* token) {
  return std::make_unique<JpegCompressorImpl>(token);
}

// static
bool JpegCompressor::IsSizeSupported(int width, int height) {
  return width > 0 && height > 0 && width % 8 == 0 && height % 2 == 0;
}

JpegCompressorImpl::JpegCompressorImpl(CameraMojoChannelManagerToken* token)
    : camera_metrics_(CameraMetrics::New()),
      hw_encoder_(nullptr),
      hw_encoder_started_(false),
      out_buffer_ptr_(nullptr),
      out_buffer_size_(0),
      out_data_size_(0),
      is_encode_success_(false),
      force_jpeg_hw_encode_for_testing_(false),
      mojo_manager_token_(token) {
  // Read force_jpeg_hw_enc configs
  std::unique_ptr<CameraConfig> camera_config =
      CameraConfig::Create(constants::kCrosCameraTestConfigPathString);
  force_jpeg_hw_encode_for_testing_ = camera_config->GetBoolean(
      constants::kCrosForceJpegHardwareEncodeOption, false);
  if (force_jpeg_hw_encode_for_testing_) {
    LOGF(INFO) << "Force JPEG hardware encode for testing";
  }
}

JpegCompressorImpl::~JpegCompressorImpl() {}

bool JpegCompressorImpl::CompressImage(const void* image,
                                       int width,
                                       int height,
                                       int quality,
                                       const void* app1_buffer,
                                       uint32_t app1_size,
                                       uint32_t out_buffer_size,
                                       void* out_buffer,
                                       uint32_t* out_data_size,
                                       bool enable_hw_encode) {
  if (!IsSizeSupported(width, height)) {
    LOGF(ERROR) << "Image size can not be handled: " << width << "x" << height;
    return false;
  }

  if (out_data_size == nullptr || out_buffer == nullptr) {
    LOGF(ERROR) << "Output should not be nullptr";
    return false;
  }

  if (app1_size > kMaxMarkerSizeAllowed) {
    LOGF(ERROR) << "App1 size " << app1_size << " > " << kMaxMarkerSizeAllowed;
    return false;
  }

  auto method_used = [&]() -> const char* {
    if (enable_hw_encode) {
      // Try HW encode.
      uint32_t input_data_size = static_cast<uint32_t>(width * height * 3 / 2);
      if (EncodeHwLegacy(static_cast<const uint8_t*>(image), input_data_size,
                         width, height,
                         static_cast<const uint8_t*>(app1_buffer), app1_size,
                         out_buffer_size, out_buffer, out_data_size)) {
        return "hardware";
      }
      if (force_jpeg_hw_encode_for_testing_) {
        return nullptr;
      }
      LOGF(WARNING) << "Tried HW encode but failed. Fall back to SW encode";
    }

    // Try SW encode.
    if (EncodeLegacy(image, width, height, quality, app1_buffer, app1_size,
                     out_buffer_size, out_buffer, out_data_size)) {
      return "software";
    }

    return nullptr;
  }();

  if (method_used == nullptr) {
    LOGF(ERROR) << "Failed to compress image with enable_hw_encode = "
                << enable_hw_encode;
    return false;
  }

  VLOGF(1) << "Compressed JPEG with " << method_used << ": "
           << (width * height * 12) / 8 << "[" << width << "x" << height
           << "] -> " << *out_data_size << " bytes";
  return true;
}

bool JpegCompressorImpl::CompressImageFromHandle(buffer_handle_t input,
                                                 buffer_handle_t output,
                                                 int width,
                                                 int height,
                                                 int quality,
                                                 const void* app1_ptr,
                                                 uint32_t app1_size,
                                                 uint32_t* out_data_size,
                                                 bool enable_hw_encode) {
  if (!IsSizeSupported(width, height)) {
    LOGF(ERROR) << "Input image size can not be handled: " << width << "x"
                << height;
    return false;
  }

  if (out_data_size == nullptr) {
    LOGF(ERROR) << "Output size should not be nullptr";
    return false;
  }

  if (app1_size > kMaxMarkerSizeAllowed) {
    LOGF(ERROR) << "App1 size " << app1_size << " > " << kMaxMarkerSizeAllowed;
    return false;
  }

  ScopedMapping input_mapping(input);
  if (!input_mapping.is_valid()) {
    LOGF(ERROR) << "Failed to map input buffer";
    return false;
  }
  if (input_mapping.v4l2_format() != V4L2_PIX_FMT_NV12 &&
      input_mapping.v4l2_format() != V4L2_PIX_FMT_NV12M) {
    LOGF(ERROR) << "Unexpected input buffer format: "
                << FormatToString(input_mapping.v4l2_format());
    return false;
  }

  ScopedMapping output_mapping(output);
  if (!output_mapping.is_valid()) {
    LOGF(ERROR) << "Failed to map output buffer";
    return false;
  }
  if (output_mapping.num_planes() != 1) {
    LOGF(ERROR) << "Unexpected output buffer format: "
                << FormatToString(output_mapping.v4l2_format());
    return false;
  }

  auto method_used = [&]() -> const char* {
    if (enable_hw_encode) {
      // Try HW encode.
      if (EncodeHw(input, output, width, height, quality, app1_ptr, app1_size,
                   out_data_size)) {
        return "hardware";
      }
      if (force_jpeg_hw_encode_for_testing_) {
        return nullptr;
      }
      LOGF(WARNING) << "Tried HW encode but failed. Fall back to SW encode";
    }

    android_ycbcr input_ycbcr = {
        .y = input_mapping.plane(0).addr,
        .cb = input_mapping.plane(1).addr,
        .cr = input_mapping.plane(1).addr + 1,
        .ystride = input_mapping.plane(0).stride,
        .cstride = input_mapping.plane(1).stride,
        .chroma_step = 2,
    };
    // Try SW encode.
    bool is_success =
        EncodeSw(input_ycbcr, input_mapping.v4l2_format(),
                 output_mapping.plane(0).addr, output_mapping.plane(0).size,
                 width, height, quality, app1_ptr, app1_size, out_data_size);

    if (is_success) {
      return "software";
    }

    return nullptr;
  }();

  if (method_used == nullptr) {
    LOGF(ERROR) << "Failed to compress image with enable_hw_encode = "
                << enable_hw_encode;
    return false;
  }

  VLOGF(1) << "Compressed JPEG with " << method_used << ": "
           << (width * height * 12) / 8 << "[" << width << "x" << height
           << "] -> " << *out_data_size << " bytes";
  return true;
}

bool JpegCompressorImpl::CompressImageFromMemory(void* input,
                                                 uint32_t input_format,
                                                 void* output,
                                                 int output_buffer_size,
                                                 int width,
                                                 int height,
                                                 int quality,
                                                 const void* app1_ptr,
                                                 uint32_t app1_size,
                                                 uint32_t* out_data_size) {
  if (!IsSizeSupported(width, height)) {
    LOGF(ERROR) << "Input image size can not be handled: " << width << "x"
                << height;
    return false;
  }

  if (out_data_size == nullptr) {
    LOGF(ERROR) << "Output size should not be nullptr";
    return false;
  }

  // Only supports NV12 packed format.
  if (input_format != V4L2_PIX_FMT_NV12) {
    LOGF(ERROR) << "Unsupported input format: " << FormatToString(input_format);
    return false;
  }
  android_ycbcr input_ycbcr{};
  input_ycbcr.y = input;
  input_ycbcr.cb = static_cast<uint8_t*>(input) + width * height;
  input_ycbcr.cr = static_cast<uint8_t*>(input) + width * height + 1;
  input_ycbcr.ystride = width;
  input_ycbcr.cstride = width;
  input_ycbcr.chroma_step = 2;

  auto isSuccess =
      EncodeSw(input_ycbcr, input_format, output, output_buffer_size, width,
               height, quality, app1_ptr, app1_size, out_data_size);
  if (isSuccess) {
    VLOGF(1) << "Compressed JPEG with software : " << (width * height * 12) / 8
             << "[" << width << "x" << height << "] -> " << *out_data_size
             << " bytes";
  } else {
    LOGF(ERROR) << "Failed to compress image with memory.";
  }
  return isSuccess;
}

bool JpegCompressorImpl::GenerateThumbnail(const void* image,
                                           int image_width,
                                           int image_height,
                                           int thumbnail_width,
                                           int thumbnail_height,
                                           int quality,
                                           uint32_t out_buffer_size,
                                           void* out_buffer,
                                           uint32_t* out_data_size) {
  if (!IsSizeSupported(thumbnail_width, thumbnail_height)) {
    LOGF(ERROR) << "Image size can not be handled: " << thumbnail_width << "x"
                << thumbnail_height;
    return false;
  }

  if (out_data_size == nullptr || out_buffer == nullptr) {
    LOGF(ERROR) << "Output should not be nullptr. ";
    return false;
  }

  // Resize |image| to |thumbnail_width| x |thumbnail_height|.
  std::vector<uint8_t> scaled_buffer;
  size_t y_plane_size = image_width * image_height;
  const uint8_t* y_plane = reinterpret_cast<const uint8_t*>(image);
  const uint8_t* u_plane = y_plane + y_plane_size;
  const uint8_t* v_plane = u_plane + y_plane_size / 4;

  size_t scaled_y_plane_size = thumbnail_width * thumbnail_height;
  scaled_buffer.resize(scaled_y_plane_size * 3 / 2);
  uint8_t* scaled_y_plane = scaled_buffer.data();
  uint8_t* scaled_u_plane = scaled_y_plane + scaled_y_plane_size;
  uint8_t* scaled_v_plane = scaled_u_plane + scaled_y_plane_size / 4;

  int result = libyuv::I420Scale(
      y_plane, image_width, u_plane, image_width / 2, v_plane, image_width / 2,
      image_width, image_height, scaled_y_plane, thumbnail_width,
      scaled_u_plane, thumbnail_width / 2, scaled_v_plane, thumbnail_width / 2,
      thumbnail_width, thumbnail_height, libyuv::kFilterNone);
  if (result != 0) {
    LOGF(ERROR) << "Generate YUV thumbnail failed";
    return false;
  }

  // Compress thumbnail to JPEG. Since thumbnail size is small, SW performs
  // better than HW.
  return CompressImage(scaled_buffer.data(), thumbnail_width, thumbnail_height,
                       quality, nullptr, 0, out_buffer_size, out_buffer,
                       out_data_size, false);
}

void JpegCompressorImpl::InitDestination(j_compress_ptr cinfo) {
  destination_mgr* dest = reinterpret_cast<destination_mgr*>(cinfo->dest);
  dest->mgr.next_output_byte = dest->compressor->out_buffer_ptr_;
  dest->mgr.free_in_buffer = dest->compressor->out_buffer_size_;
  dest->compressor->is_encode_success_ = true;
}

boolean JpegCompressorImpl::EmptyOutputBuffer(j_compress_ptr cinfo) {
  destination_mgr* dest = reinterpret_cast<destination_mgr*>(cinfo->dest);
  dest->mgr.next_output_byte = dest->compressor->out_buffer_ptr_;
  dest->mgr.free_in_buffer = dest->compressor->out_buffer_size_;
  dest->compressor->is_encode_success_ = false;
  // jcmarker.c in libjpeg-turbo will trigger exit(EXIT_FAILURE) if buffer is
  // not enough to fill marker. If we want to solve this failure, we have to
  // override cinfo.err->error_exit. It's too complicated. Therefore, we use a
  // variable |is_encode_success_| to indicate error and always return true
  // here.
  return true;
}

void JpegCompressorImpl::TerminateDestination(j_compress_ptr cinfo) {
  destination_mgr* dest = reinterpret_cast<destination_mgr*>(cinfo->dest);
  dest->compressor->out_data_size_ =
      dest->compressor->out_buffer_size_ - dest->mgr.free_in_buffer;
}

void JpegCompressorImpl::OutputErrorMessage(j_common_ptr cinfo) {
  char buffer[JMSG_LENGTH_MAX];

  /* Create the message */
  (*cinfo->err->format_message)(cinfo, buffer);
  LOGF(ERROR) << buffer;
}

bool JpegCompressorImpl::EncodeHwLegacy(const uint8_t* input_buffer,
                                        uint32_t input_buffer_size,
                                        int width,
                                        int height,
                                        const uint8_t* app1_buffer,
                                        uint32_t app1_buffer_size,
                                        uint32_t out_buffer_size,
                                        void* out_buffer,
                                        uint32_t* out_data_size) {
  base::ElapsedTimer timer;
  if (!hw_encoder_) {
    hw_encoder_ =
        cros::JpegEncodeAccelerator::CreateInstance(mojo_manager_token_);
    hw_encoder_started_ = hw_encoder_->Start();
  }

  if (!hw_encoder_ || !hw_encoder_started_) {
    return false;
  }

  // Create SharedMemory for output buffer.
  base::WritableSharedMemoryRegion output_shm_region =
      base::WritableSharedMemoryRegion::Create(out_buffer_size);
  if (!output_shm_region.IsValid()) {
    LOGF(ERROR) << "Create shared memory region for output buffer failed, size="
                << out_buffer_size;
    return false;
  }
  base::WritableSharedMemoryMapping output_shm_mapping =
      output_shm_region.Map();
  if (!output_shm_mapping.IsValid()) {
    LOGF(ERROR) << "Create mapping for output buffer failed, size="
                << out_buffer_size;
    return false;
  }
  base::subtle::PlatformSharedMemoryRegion platform_shm =
      base::WritableSharedMemoryRegion::TakeHandleForSerialization(
          std::move(output_shm_region));

  // Utilize HW Jpeg encode through IPC.
  int status = hw_encoder_->EncodeSync(
      -1, input_buffer, input_buffer_size, static_cast<int32_t>(width),
      static_cast<int32_t>(height), app1_buffer, app1_buffer_size,
      platform_shm.GetPlatformHandle().fd,
      static_cast<uint32_t>(out_buffer_size), out_data_size);
  if (status == cros::JpegEncodeAccelerator::TRY_START_AGAIN) {
    // There might be some mojo errors. We will give a second try.
    LOGF(WARNING) << "EncodeSync() returns TRY_START_AGAIN.";
    hw_encoder_started_ = hw_encoder_->Start();
    if (hw_encoder_started_) {
      status = hw_encoder_->EncodeSync(
          -1, input_buffer, input_buffer_size, static_cast<int32_t>(width),
          static_cast<int32_t>(height), app1_buffer, app1_buffer_size,
          platform_shm.GetPlatformHandle().fd,
          static_cast<uint32_t>(out_buffer_size), out_data_size);
    } else {
      LOGF(ERROR) << "JPEG encode accelerator can't be started.";
    }
  }
  if (status == cros::JpegEncodeAccelerator::ENCODE_OK) {
    memcpy(static_cast<unsigned char*>(out_buffer), output_shm_mapping.memory(),
           *out_data_size);
    camera_metrics_->SendJpegProcessLatency(JpegProcessType::kEncode,
                                            JpegProcessMethod::kHardware,
                                            timer.Elapsed());
    camera_metrics_->SendJpegResolution(
        JpegProcessType::kEncode, JpegProcessMethod::kHardware, width, height);
    return true;
  } else {
    LOGF(ERROR) << "HW encode failed with " << status;
  }

  return false;
}

bool JpegCompressorImpl::EncodeLegacy(const void* inYuv,
                                      int width,
                                      int height,
                                      int jpeg_quality,
                                      const void* app1_buffer,
                                      unsigned int app1_size,
                                      uint32_t out_buffer_size,
                                      void* out_buffer,
                                      uint32_t* out_data_size) {
  base::ElapsedTimer timer;
  out_buffer_ptr_ = static_cast<JOCTET*>(out_buffer);
  out_buffer_size_ = out_buffer_size;

  jpeg_compress_struct cinfo;
  jpeg_error_mgr jerr;

  cinfo.err = jpeg_std_error(&jerr);
  // Override output_message() to print error log with ALOGE().
  cinfo.err->output_message = &OutputErrorMessage;
  jpeg_create_compress(&cinfo);
  SetJpegDestination(&cinfo);

  SetJpegCompressStruct(width, height, jpeg_quality, &cinfo);
  jpeg_start_compress(&cinfo, TRUE);

  if (app1_buffer != nullptr && app1_size > 0) {
    jpeg_write_marker(&cinfo, JPEG_APP0 + 1,
                      static_cast<const JOCTET*>(app1_buffer), app1_size);
  }

  if (!Compress(&cinfo, static_cast<const uint8_t*>(inYuv))) {
    is_encode_success_ = false;
  }

  jpeg_finish_compress(&cinfo);
  jpeg_destroy_compress(&cinfo);

  if (is_encode_success_) {
    *out_data_size = out_data_size_;
  }

  if (is_encode_success_) {
    camera_metrics_->SendJpegProcessLatency(JpegProcessType::kEncode,
                                            JpegProcessMethod::kSoftware,
                                            timer.Elapsed());
    camera_metrics_->SendJpegResolution(
        JpegProcessType::kEncode, JpegProcessMethod::kSoftware, width, height);
  }
  return is_encode_success_;
}

bool JpegCompressorImpl::EncodeHw(buffer_handle_t input_handle,
                                  buffer_handle_t output_handle,
                                  int width,
                                  int height,
                                  int quality,
                                  const void* app1_ptr,
                                  uint32_t app1_size,
                                  uint32_t* out_data_size) {
  base::ElapsedTimer timer;
  if (input_handle == nullptr || output_handle == nullptr) {
    if (input_handle == nullptr) {
      LOGF(INFO) << "Input handle is nullptr.";
    }
    if (output_handle == nullptr) {
      LOGF(INFO) << "Output handle is nullptr.";
    }
    return false;
  }

  uint32_t input_format =
      cros::CameraBufferManager::GetV4L2PixelFormat(input_handle);
  DCHECK(input_format == V4L2_PIX_FMT_NV12 ||
         input_format == V4L2_PIX_FMT_NV12M);

  std::vector<JpegCompressor::DmaBufPlane> input_planes;
  uint32_t input_num_planes =
      cros::CameraBufferManager::GetNumPlanes(input_handle);
  if (input_num_planes == 0) {
    LOGF(INFO) << "Input buffer handle is invalid.";
    return false;
  } else {
    for (int i = 0; i < input_num_planes; i++) {
      JpegCompressor::DmaBufPlane plane;
      plane.fd = input_handle->data[i];
      plane.stride = cros::CameraBufferManager::GetPlaneStride(input_handle, i);
      plane.offset = cros::CameraBufferManager::GetPlaneOffset(input_handle, i);
      plane.size = cros::CameraBufferManager::GetPlaneSize(input_handle, i);
      input_planes.push_back(std::move(plane));
    }
  }

  std::vector<JpegCompressor::DmaBufPlane> output_planes;
  uint32_t output_num_planes =
      cros::CameraBufferManager::GetNumPlanes(output_handle);
  if (output_num_planes == 0) {
    LOGF(INFO) << "Output buffer handle is invalid.";
    return false;
  } else {
    for (int i = 0; i < output_num_planes; i++) {
      JpegCompressor::DmaBufPlane plane;
      plane.fd = output_handle->data[i];
      plane.stride =
          cros::CameraBufferManager::GetPlaneStride(output_handle, i);
      plane.offset =
          cros::CameraBufferManager::GetPlaneOffset(output_handle, i);
      plane.size = cros::CameraBufferManager::GetPlaneSize(output_handle, i);
      output_planes.push_back(std::move(plane));
    }
  }

  if (!hw_encoder_) {
    hw_encoder_ =
        cros::JpegEncodeAccelerator::CreateInstance(mojo_manager_token_);
    hw_encoder_started_ = hw_encoder_->Start();
  }

  if (!hw_encoder_ || !hw_encoder_started_) {
    LOGF(INFO) << "Hw encoder is not started";
    return false;
  }

  const uint64_t input_modifier =
      cros::CameraBufferManager::GetModifier(input_handle);
  int status = hw_encoder_->EncodeSync(
      input_format, std::move(input_planes), std::move(output_planes),
      static_cast<const uint8_t*>(app1_ptr), app1_size, width, height, quality,
      input_modifier, out_data_size);
  if (status == cros::JpegEncodeAccelerator::TRY_START_AGAIN) {
    // There might be some mojo errors. We will give a second try.
    LOGF(WARNING) << "EncodeSync() returns TRY_START_AGAIN.";
    hw_encoder_started_ = hw_encoder_->Start();
    if (hw_encoder_started_) {
      status = hw_encoder_->EncodeSync(
          input_format, std::move(input_planes), std::move(output_planes),
          static_cast<const uint8_t*>(app1_ptr), app1_size, width, height,
          quality, input_modifier, out_data_size);
    } else {
      LOGF(ERROR) << "JPEG encode accelerator can't be started.";
    }
  }
  if (status == cros::JpegEncodeAccelerator::ENCODE_OK) {
    camera_metrics_->SendJpegProcessLatency(JpegProcessType::kEncode,
                                            JpegProcessMethod::kHardware,
                                            timer.Elapsed());
    camera_metrics_->SendJpegResolution(
        JpegProcessType::kEncode, JpegProcessMethod::kHardware, width, height);
    return true;
  } else {
    LOGF(ERROR) << "HW encode failed with " << status;
  }
  return false;
}

bool JpegCompressorImpl::EncodeSw(const android_ycbcr& input_ycbcr,
                                  uint32_t input_format,
                                  void* output_ptr,
                                  int output_buffer_size,
                                  int width,
                                  int height,
                                  int jpeg_quality,
                                  const void* app1_buffer,
                                  unsigned int app1_size,
                                  uint32_t* out_data_size) {
  base::ElapsedTimer timer;
  if (!input_ycbcr.y || !input_ycbcr.cb || !input_ycbcr.cr) {
    LOGF(INFO) << "Input ptr is null.";
    return false;
  }
  if (output_ptr == nullptr) {
    LOGF(INFO) << "Output ptr is null.";
    return false;
  }

  DCHECK(input_format == V4L2_PIX_FMT_NV12 ||
         input_format == V4L2_PIX_FMT_NV12M);

  size_t y_plane_size = width * height;

  std::vector<uint8_t> i420_buffer;
  i420_buffer.resize(y_plane_size * 3 / 2);
  uint8_t* i420_y_plane = i420_buffer.data();
  uint8_t* i420_u_plane = i420_y_plane + y_plane_size;
  uint8_t* i420_v_plane = i420_u_plane + y_plane_size / 4;

  int result = libyuv::NV12ToI420(
      static_cast<const uint8_t*>(input_ycbcr.y), input_ycbcr.ystride,
      static_cast<const uint8_t*>(input_ycbcr.cb), input_ycbcr.cstride,
      i420_y_plane, width, i420_u_plane, width / 2, i420_v_plane, width / 2,
      width, height);
  if (result != 0) {
    LOGF(INFO) << "Failed to convert image format when doing SW encoding: "
               << result;
    return false;
  }

  out_buffer_ptr_ = static_cast<JOCTET*>(output_ptr);
  out_buffer_size_ = output_buffer_size;

  jpeg_compress_struct cinfo;
  jpeg_error_mgr jerr;

  cinfo.err = jpeg_std_error(&jerr);
  // Override output_message() to print error log with ALOGE().
  cinfo.err->output_message = &OutputErrorMessage;
  jpeg_create_compress(&cinfo);
  SetJpegDestination(&cinfo);

  SetJpegCompressStruct(width, height, jpeg_quality, &cinfo);

  if (app1_buffer != nullptr && app1_size > 0) {
    cinfo.write_Adobe_marker = false;
    cinfo.write_JFIF_header = false;
  }

  jpeg_start_compress(&cinfo, TRUE);

  if (app1_buffer != nullptr && app1_size > 0) {
    jpeg_write_marker(&cinfo, JPEG_APP0 + 1,
                      static_cast<const JOCTET*>(app1_buffer), app1_size);
  }

  if (!Compress(&cinfo, static_cast<const uint8_t*>(i420_y_plane))) {
    is_encode_success_ = false;
  }
  jpeg_finish_compress(&cinfo);
  jpeg_destroy_compress(&cinfo);

  if (is_encode_success_) {
    *out_data_size = out_data_size_;
    camera_metrics_->SendJpegProcessLatency(JpegProcessType::kEncode,
                                            JpegProcessMethod::kSoftware,
                                            timer.Elapsed());
    camera_metrics_->SendJpegResolution(
        JpegProcessType::kEncode, JpegProcessMethod::kSoftware, width, height);
  }
  return is_encode_success_;
}

void JpegCompressorImpl::SetJpegDestination(jpeg_compress_struct* cinfo) {
  destination_mgr* dest =
      static_cast<struct destination_mgr*>((*cinfo->mem->alloc_small)(
          (j_common_ptr)cinfo, JPOOL_PERMANENT, sizeof(destination_mgr)));
  dest->compressor = this;
  dest->mgr.init_destination = &InitDestination;
  dest->mgr.empty_output_buffer = &EmptyOutputBuffer;
  dest->mgr.term_destination = &TerminateDestination;
  cinfo->dest = reinterpret_cast<struct jpeg_destination_mgr*>(dest);
}

void JpegCompressorImpl::SetJpegCompressStruct(int width,
                                               int height,
                                               int quality,
                                               jpeg_compress_struct* cinfo) {
  cinfo->image_width = width;
  cinfo->image_height = height;
  cinfo->input_components = 3;
  cinfo->in_color_space = JCS_YCbCr;
  jpeg_set_defaults(cinfo);

  jpeg_set_quality(cinfo, quality, TRUE);
  jpeg_set_colorspace(cinfo, JCS_YCbCr);
  cinfo->raw_data_in = TRUE;
  cinfo->dct_method = JDCT_IFAST;

  // Configure sampling factors. The sampling factor is JPEG subsampling 420
  // because the source format is YUV420.
  cinfo->comp_info[0].h_samp_factor = 2;
  cinfo->comp_info[0].v_samp_factor = 2;
  cinfo->comp_info[1].h_samp_factor = 1;
  cinfo->comp_info[1].v_samp_factor = 1;
  cinfo->comp_info[2].h_samp_factor = 1;
  cinfo->comp_info[2].v_samp_factor = 1;
}

bool JpegCompressorImpl::Compress(jpeg_compress_struct* cinfo,
                                  const uint8_t* yuv) {
  JSAMPROW y[kCompressBatchSize];
  JSAMPROW cb[kCompressBatchSize / 2];
  JSAMPROW cr[kCompressBatchSize / 2];
  JSAMPARRAY planes[3]{y, cb, cr};

  size_t y_plane_size = cinfo->image_width * cinfo->image_height;
  size_t uv_plane_size = y_plane_size / 4;
  uint8_t* y_plane = const_cast<uint8_t*>(yuv);
  uint8_t* u_plane = const_cast<uint8_t*>(yuv + y_plane_size);
  uint8_t* v_plane = const_cast<uint8_t*>(yuv + y_plane_size + uv_plane_size);
  std::unique_ptr<uint8_t[]> empty(new uint8_t[cinfo->image_width]);
  memset(empty.get(), 0, cinfo->image_width);

  while (cinfo->next_scanline < cinfo->image_height) {
    for (int i = 0; i < kCompressBatchSize; ++i) {
      size_t scanline = cinfo->next_scanline + i;
      if (scanline < cinfo->image_height) {
        y[i] = y_plane + scanline * cinfo->image_width;
      } else {
        y[i] = empty.get();
      }
    }
    // cb, cr only have half scanlines
    for (int i = 0; i < kCompressBatchSize / 2; ++i) {
      size_t scanline = cinfo->next_scanline / 2 + i;
      if (scanline < cinfo->image_height / 2) {
        int offset = scanline * (cinfo->image_width / 2);
        cb[i] = u_plane + offset;
        cr[i] = v_plane + offset;
      } else {
        cb[i] = cr[i] = empty.get();
      }
    }

    int processed = jpeg_write_raw_data(cinfo, planes, kCompressBatchSize);
    if (processed != kCompressBatchSize) {
      LOGF(ERROR) << "Number of processed lines does not equal input lines.";
      return false;
    }
  }
  return true;
}

}  // namespace cros
