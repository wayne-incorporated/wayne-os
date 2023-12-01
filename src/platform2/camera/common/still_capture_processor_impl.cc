/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/still_capture_processor_impl.h"

#include <algorithm>
#include <optional>
#include <utility>

#include <libyuv/scale.h>
#include <linux/videodev2.h>
#include <sync/sync.h>

#include "common/common_tracing.h"
#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/common.h"
#include "cros-camera/exif_utils.h"

namespace cros {

namespace {

constexpr size_t kJpegMarkerSize = 2;
constexpr size_t kJpegLengthSize = 2;
constexpr uint16_t kJpegSOF0 = 0xFFC0;
constexpr uint16_t kJpegSOF2 = 0xFFC2;
constexpr uint16_t kJpegDHT = 0xFFC4;
constexpr uint16_t kJpegRST0 = 0xFFD0;
constexpr uint16_t kJpegRST1 = 0xFFD1;
constexpr uint16_t kJpegRST2 = 0xFFD2;
constexpr uint16_t kJpegRST3 = 0xFFD3;
constexpr uint16_t kJpegRST4 = 0xFFD4;
constexpr uint16_t kJpegRST5 = 0xFFD5;
constexpr uint16_t kJpegRST6 = 0xFFD6;
constexpr uint16_t kJpegRST7 = 0xFFD7;
constexpr uint16_t kJpegSOF = 0xFFD8;
constexpr uint16_t kJpegEOI = 0xFFD9;
constexpr uint16_t kJpegSOS = 0xFFDA;
constexpr uint16_t kJpegDQT = 0xFFDB;
constexpr uint16_t kJpegDRI = 0xFFDD;
constexpr uint16_t kJpegAPP0 = 0xFFE0;
constexpr uint16_t kJpegAPP1 = 0xFFE1;
constexpr uint16_t kJpegAPP2 = 0xFFE2;
constexpr uint16_t kJpegAPP3 = 0xFFE3;
constexpr uint16_t kJpegAPP4 = 0xFFE4;
constexpr uint16_t kJpegAPP5 = 0xFFE5;
constexpr uint16_t kJpegAPP6 = 0xFFE6;
constexpr uint16_t kJpegAPP7 = 0xFFE7;
constexpr uint16_t kJpegAPP8 = 0xFFE8;
constexpr uint16_t kJpegAPP9 = 0xFFE9;
constexpr uint16_t kJpegAPP10 = 0xFFEA;
constexpr uint16_t kJpegAPP11 = 0xFFEB;
constexpr uint16_t kJpegAPP12 = 0xFFEC;
constexpr uint16_t kJpegAPP13 = 0xFFED;
constexpr uint16_t kJpegAPP14 = 0xFFEE;
constexpr uint16_t kJpegAPP15 = 0xFFEF;
constexpr uint16_t kJpegCOM = 0xFFFE;

void InsertJpegBlobDescriptor(buffer_handle_t jpeg_blob,
                              uint32_t jpeg_data_size) {
  ScopedMapping mapping(jpeg_blob);
  size_t buffer_size = CameraBufferManager::GetPlaneSize(jpeg_blob, 0);
  camera3_jpeg_blob_t* blob = reinterpret_cast<camera3_jpeg_blob_t*>(
      static_cast<uint8_t*>(mapping.plane(0).addr) + buffer_size -
      sizeof(camera3_jpeg_blob_t));
  blob->jpeg_blob_id = CAMERA3_JPEG_BLOB_ID;
  blob->jpeg_size = jpeg_data_size;
}

bool ParseAppSections(base::span<uint8_t> blob,
                      std::vector<uint8_t>* out_buffer,
                      std::map<uint16_t, base::span<uint8_t>>* out_index) {
  if (blob.empty())
    return false;
  out_buffer->resize(blob.size());
  uint8_t* src_addr = blob.data();
  const uint8_t* src_end = blob.data() + blob.size();
  size_t dst_offset = 0;
  while (src_addr < src_end) {
    auto parse_word = [](uint8_t* addr) -> uint16_t {
      return (*addr << 8) + *(addr + 1);
    };

    if (src_addr + 2 > src_end) {
      LOGF(ERROR) << "Incomplete marker";
      return false;
    }
    uint16_t marker = parse_word(src_addr);
    VLOGF(2) << "Marker: " << std::hex << marker;
    switch (marker) {
      case kJpegSOF:
      case kJpegRST0:
      case kJpegRST1:
      case kJpegRST2:
      case kJpegRST3:
      case kJpegRST4:
      case kJpegRST5:
      case kJpegRST6:
      case kJpegRST7:
      case kJpegEOI:
        // Skip the marker as there's no payload.
        src_addr += kJpegMarkerSize;
        break;

      case kJpegSOF0:
      case kJpegSOF2:
      case kJpegDHT:
      case kJpegDQT:
      case kJpegDRI:
      case kJpegSOS:
        // Skip the marker and the payload.
        if (src_addr + kJpegMarkerSize + kJpegLengthSize > src_end) {
          LOGF(ERROR) << "Invalid JPEG header";
          return false;
        }
        src_addr += (kJpegMarkerSize + parse_word(src_addr + kJpegMarkerSize));
        break;

      case kJpegAPP0:
      case kJpegAPP1:
      case kJpegAPP2:
      case kJpegAPP3:
      case kJpegAPP4:
      case kJpegAPP5:
      case kJpegAPP6:
      case kJpegAPP7:
      case kJpegAPP8:
      case kJpegAPP9:
      case kJpegAPP10:
      case kJpegAPP11:
      case kJpegAPP12:
      case kJpegAPP13:
      case kJpegAPP14:
      case kJpegAPP15:
      case kJpegCOM: {
        // Copy out the APPn/COM marker and payload.
        if (src_addr + kJpegMarkerSize + kJpegLengthSize > src_end) {
          LOGF(ERROR) << "Invalid JPEG header";
          return false;
        }
        size_t segment_size =
            kJpegMarkerSize + parse_word(src_addr + kJpegMarkerSize);
        if (src_addr + segment_size > src_end) {
          LOGF(ERROR) << "Invalid JPEG header";
          return false;
        }
        std::copy(src_addr, src_addr + segment_size,
                  out_buffer->data() + dst_offset);
        if (out_index->count(marker)) {
          LOGF(ERROR) << "Found duplicated JPEG marker: 0x" << std::hex
                      << marker;
        }
        out_index->insert(
            {marker, {out_buffer->data() + dst_offset, segment_size}});
        dst_offset += segment_size;
        src_addr += segment_size;
        break;
      }

      default:
        LOGF(ERROR) << "Invalid JPEG marker: 0x" << std::hex << marker;
        return false;
    }

    // Assuming that the APPn markers always appear before SOS.
    if (marker == kJpegSOS || marker == kJpegEOI) {
      break;
    }
  }

  out_buffer->resize(dst_offset);
  return true;
}

bool ExtractAppSections(buffer_handle_t blob_buffer,
                        std::vector<uint8_t>* out_buffer,
                        std::map<uint16_t, base::span<uint8_t>>* out_index) {
  ScopedMapping mapping(blob_buffer);
  return ParseAppSections(
      base::make_span(mapping.plane(0).addr, mapping.plane(0).size), out_buffer,
      out_index);
}

// Compupte the cropped region of size (|out_width|, |out_height|) out of the
// src region (|src_width|, |src_height|) such that (|out_width|, |out_height|)
// has the same aspect ratio as (|dst_width|, |dst_height|). The out region can
// be obtained by reading out the |src_width| x |src_height| region from the
// starting coordinate (|out_start_x|, |out_start_y|).
void GetCropSizeAndXySkips(int src_width,
                           int src_height,
                           int dst_width,
                           int dst_height,
                           int* out_width,
                           int* out_height,
                           int* out_start_x,
                           int* out_start_y) {
  CHECK_GE(src_width, dst_width);
  CHECK_GE(src_height, dst_height);
  if (src_width * dst_height == src_height * dst_width) {
    *out_width = src_width;
    *out_height = src_height;
    *out_start_x = 0;
    *out_start_y = 0;
  } else if (static_cast<float>(src_width) / src_height >
             static_cast<float>(dst_width) / dst_height) {
    // Crop left and right of the src.
    *out_width = dst_width * src_height / dst_height;
    *out_height = src_height;  // dst_height * src_height / dst_height
    *out_start_x = (src_width - *out_width) / 2;
    *out_start_y = 0;
  } else {
    // Crop top and bottom of the src.
    *out_width = src_width;  // dst_width * src_width / dst_width
    *out_height = dst_height * src_width / dst_width;
    *out_start_x = 0;
    *out_start_y = (src_height - *out_height) / 2;
  }
}

inline uint8_t HighByte(uint16_t value) {
  return (value >> 8) & 0xFF;
}

inline uint8_t LowByte(uint16_t value) {
  return value & 0xFF;
}

inline uint8_t* WriteTwoBytes(uint8_t* dst, uint16_t value) {
  dst[0] = HighByte(value);
  dst[1] = LowByte(value);
  return dst + 2;
}

}  // namespace

StillCaptureProcessorImpl::StillCaptureProcessorImpl(
    std::unique_ptr<JpegCompressor> jpeg_compressor)
    : thread_("StillCaptureProcessorImplThread"),
      jpeg_compressor_(std::move(jpeg_compressor)) {}

StillCaptureProcessorImpl::~StillCaptureProcessorImpl() {
  Reset();
}

void StillCaptureProcessorImpl::Initialize(
    const camera3_stream_t* const still_capture_stream,
    CaptureResultCallback result_callback) {
  TRACE_COMMON("width", still_capture_stream->width, "height",
               still_capture_stream->height);

  blob_stream_ = still_capture_stream;
  result_callback_ = std::move(result_callback);
  request_contexts_.clear();
  CHECK(thread_.Start());
}

void StillCaptureProcessorImpl::Reset() {
  TRACE_COMMON();

  thread_.Stop();
  blob_stream_ = nullptr;
  result_callback_ = base::NullCallback();
  request_contexts_.clear();
}

void StillCaptureProcessorImpl::QueuePendingOutputBuffer(
    int frame_number,
    camera3_stream_buffer_t output_buffer,
    const Camera3CaptureDescriptor& request) {
  auto buf_mgr = CameraBufferManager::GetInstance();
  RequestContext req = {
      .jpeg_blob = buf_mgr->AllocateScopedBuffer(
          CameraBufferManager::GetPlaneSize(*output_buffer.buffer, 0), 1,
          HAL_PIXEL_FORMAT_BLOB, output_buffer.stream->usage),
      .client_requested_buffer = output_buffer,
  };
  if (!req.jpeg_blob) {
    LOGF(ERROR) << "Cannot allocated JPEG buffer";
    return;
  }
  base::span<const int32_t> thumbnail_size =
      request.GetMetadata<int32_t>(ANDROID_JPEG_THUMBNAIL_SIZE);
  if (thumbnail_size.size() == 2) {
    req.thumbnail_size = {static_cast<uint32_t>(thumbnail_size[0]),
                          static_cast<uint32_t>(thumbnail_size[1])};
  }
  base::span<const uint8_t> thumbnail_quality =
      request.GetMetadata<uint8_t>(ANDROID_JPEG_THUMBNAIL_QUALITY);
  if (!thumbnail_quality.empty()) {
    req.thumbnail_quality = thumbnail_quality[0];
  }
  base::span<const uint8_t> jpeg_quality =
      request.GetMetadata<uint8_t>(ANDROID_JPEG_QUALITY);
  if (!jpeg_quality.empty()) {
    req.jpeg_quality = jpeg_quality[0];
  }

  VLOGFID(1, frame_number) << "Output buffer queued. thumbnail_size = "
                           << req.thumbnail_size.ToString()
                           << " thumbnail_quality=" << req.thumbnail_quality
                           << " jpeg_quality=" << req.jpeg_quality;
  thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &StillCaptureProcessorImpl::QueuePendingOutputBufferOnThread,
          base::Unretained(this), frame_number, std::move(req)));
}

void StillCaptureProcessorImpl::QueuePendingAppsSegments(
    int frame_number,
    buffer_handle_t blob_buffer,
    base::ScopedFD release_fence) {
  VLOGFID(1, frame_number) << "APPs segments queued";

  std::vector<uint8_t> apps_segments_buffer;
  std::map<uint16_t, base::span<uint8_t>> apps_segments_index;
  // We can't assume anything on the life-time of |blob_buffer|, so we need to
  // copy the data out from the buffer.
  if (release_fence.is_valid() && sync_wait(release_fence.get(), 300) != 0) {
    LOGF(ERROR) << "sync_wait timeout on BLOB buffer";
  } else if (!ExtractAppSections(blob_buffer, &apps_segments_buffer,
                                 &apps_segments_index)) {
    LOGF(ERROR) << "Cannot extract JPEG APPs segments";
    apps_segments_buffer.clear();
    apps_segments_index.clear();
  }
  // We can still produce the JPEG image without the metadata.
  thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &StillCaptureProcessorImpl::QueuePendingAppsSegmentsOnThread,
          base::Unretained(this), frame_number, std::move(apps_segments_buffer),
          std::move(apps_segments_index)));
}

void StillCaptureProcessorImpl::QueuePendingYuvImage(
    int frame_number,
    buffer_handle_t yuv_buffer,
    base::ScopedFD release_fence) {
  VLOGFID(1, frame_number) << "YUV image queued";
  thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&StillCaptureProcessorImpl::QueuePendingYuvImageOnThread,
                     base::Unretained(this), frame_number, yuv_buffer,
                     std::move(release_fence)));
}

void StillCaptureProcessorImpl::QueuePendingOutputBufferOnThread(
    int frame_number, RequestContext request_context) {
  DCHECK(thread_.task_runner()->BelongsToCurrentThread());
  TRACE_COMMON("frame_number", frame_number, "width",
               request_context.client_requested_buffer.stream->width, "height",
               request_context.client_requested_buffer.stream->height);

  request_contexts_.insert({frame_number, std::move(request_context)});
}

void StillCaptureProcessorImpl::QueuePendingAppsSegmentsOnThread(
    int frame_number,
    std::vector<uint8_t> apps_segments_buffer,
    std::map<uint16_t, base::span<uint8_t>> apps_segments_index) {
  DCHECK(thread_.task_runner()->BelongsToCurrentThread());
  TRACE_COMMON("frame_number", frame_number);

  if (request_contexts_.count(frame_number) == 0) {
    LOGF(ERROR) << "No output buffer queued";
    return;
  }

  RequestContext& context = request_contexts_[frame_number];
  context.apps_segments_buffer = std::move(apps_segments_buffer);
  context.apps_segments_index = std::move(apps_segments_index);
  context.has_apps_segments = true;

  MaybeProduceCaptureResultOnThread(frame_number);
}

void StillCaptureProcessorImpl::QueuePendingYuvImageOnThread(
    int frame_number,
    buffer_handle_t yuv_buffer,
    base::ScopedFD release_fence) {
  DCHECK(thread_.task_runner()->BelongsToCurrentThread());
  TRACE_COMMON("frame_number", frame_number);

  if (request_contexts_.count(frame_number) == 0) {
    LOGF(ERROR) << "No output buffer queued";
    return;
  }

  RequestContext& context = request_contexts_[frame_number];
  {
    TRACE_COMMON_EVENT(
        "StillCaptureProcessorImpl::QueuePendingYuvImageOnThread::EncodeJPEG",
        "frame_number", frame_number);

    if (release_fence.is_valid() && sync_wait(release_fence.get(), 1000) != 0) {
      LOGF(ERROR) << "sync_wait timeout on YUV buffer";
      // TODO(jcliang): Notify buffer error here.
      return;
    }
    if (!jpeg_compressor_->CompressImageFromHandle(
            yuv_buffer, *context.jpeg_blob, blob_stream_->width,
            blob_stream_->height, context.jpeg_quality, nullptr, 0,
            &context.jpeg_blob_size, /*enable_hw_encode=*/false)) {
      LOGF(ERROR) << "Cannot encode YUV image to JPEG";
      // TODO(jcliang): Notify buffer error here.
      return;
    }
  }
  context.has_jpeg = true;
  if (context.thumbnail_size.area() > 0) {
    TRACE_COMMON_EVENT(
        "StillCaptureProcessorImpl::QueuePendingYuvImageOnThread::"
        "GenerateThumbnail",
        "frame_number", frame_number);

    // Scale down the YUV image and produce JPEG thumbnail.
    ScopedMapping mapping(yuv_buffer);
    std::vector<uint8_t> scaled_nv12(context.thumbnail_size.area() * 3 / 2);
    // If the thumbnail image aspect ratio is different from the primary JPEG
    // image, we need to crop the main image first before scaling.
    int src_width, src_height, src_x_start, src_y_start;
    GetCropSizeAndXySkips(mapping.width(), mapping.height(),
                          context.thumbnail_size.width,
                          context.thumbnail_size.height, &src_width,
                          &src_height, &src_x_start, &src_y_start);
    int y_plane_start = src_x_start + src_y_start * mapping.plane(0).stride;
    // UV plane has 2:1 subsampling with 2 bytes per pixel.
    int uv_plane_start =
        (src_x_start / 2) * 2 + (src_y_start / 2) * mapping.plane(1).stride;
    uint8_t* dst_y = scaled_nv12.data();
    int dst_stride_y = context.thumbnail_size.width;
    uint8_t* dst_uv = scaled_nv12.data() + context.thumbnail_size.area();
    int dst_stride_uv = context.thumbnail_size.width / 2 * 2;
    if (libyuv::NV12Scale(
            mapping.plane(0).addr + y_plane_start, mapping.plane(0).stride,
            mapping.plane(1).addr + uv_plane_start, mapping.plane(1).stride,
            src_width, src_height, dst_y, dst_stride_y, dst_uv, dst_stride_uv,
            context.thumbnail_size.width, context.thumbnail_size.height,
            libyuv::kFilterBilinear)) {
      LOGF(ERROR) << "Cannot downscale YUV image to produce thumbnail";
    }

    // This leaves 15533 bytes of space for other metadata in APP1 segment.
    constexpr int kThumbnailSizeLimit = 50000;
    uint32_t thumbnail_data_size = 0;
    int thumbnail_quality = context.thumbnail_quality;
    context.thumbnail_buffer.resize(context.thumbnail_size.area() * 2);
    do {
      auto ret = jpeg_compressor_->CompressImageFromMemory(
          scaled_nv12.data(), V4L2_PIX_FMT_NV12,
          context.thumbnail_buffer.data(), context.thumbnail_buffer.size(),
          context.thumbnail_size.width, context.thumbnail_size.height,
          thumbnail_quality, nullptr, 0, &thumbnail_data_size);
      if (!ret) {
        LOGF(ERROR) << "Cannot produce JPEG thumbnail image";
        thumbnail_data_size = 0;
        break;
      }
      thumbnail_quality -= 10;
    } while (thumbnail_data_size > kThumbnailSizeLimit &&
             thumbnail_quality > 0);
    context.thumbnail_buffer.resize(thumbnail_data_size);
    VLOGFID(1, frame_number)
        << "Produced thumbnail with size=" << context.thumbnail_size.ToString()
        << " data_length=" << thumbnail_data_size;
  }

  MaybeProduceCaptureResultOnThread(frame_number);
}

void StillCaptureProcessorImpl::MaybeProduceCaptureResultOnThread(
    int frame_number) {
  DCHECK(thread_.task_runner()->BelongsToCurrentThread());
  DCHECK_EQ(request_contexts_.count(frame_number), 1);
  TRACE_COMMON("frame_number", frame_number);

  RequestContext& context = request_contexts_.at(frame_number);
  if (!(context.has_apps_segments && context.has_jpeg)) {
    return;
  }

  VLOGFID(1, frame_number) << "Producing JPEG";
  {
    ScopedMapping result_mapping(*context.client_requested_buffer.buffer);
    uint8_t* dst_start = result_mapping.plane(0).addr;
    uint8_t* dst_addr = dst_start;

    // Write the SOF marker.
    dst_addr = WriteTwoBytes(dst_addr, kJpegSOF);

    // Copy the APPn segments from vendor camera HAL.
    for (auto it = context.apps_segments_index.begin();
         it != context.apps_segments_index.end(); ++it) {
      switch (it->first) {
        case kJpegAPP0:
          // Skip APP0 as we're going to use the one produced by the encoder
          // below.
          break;

        case kJpegAPP1: {
          if (context.thumbnail_size.area() > 0 &&
              context.thumbnail_buffer.size() > 0) {
            VLOGFID(1, frame_number) << "Write JPEG segment 0x" << std::hex
                                     << it->first << " with thumbnail";
            // Thumbnail requested and available, so replace the thumbnail.
            ExifUtils exif_utils;
            if (!exif_utils.InitializeWithData(it->second)) {
              LOGF(ERROR) << "Cannot load APPs segments";
              break;
            }
            if (!exif_utils.GenerateApp1(context.thumbnail_buffer.data(),
                                         context.thumbnail_buffer.size())) {
              LOGF(ERROR) << "Cannot generate APP1 segment with thumbnail";
              break;
            }

            // Write the APP1 marker.
            dst_addr = WriteTwoBytes(dst_addr, kJpegAPP1);

            // Write the segment size of the APP1 segment.
            const uint8_t* app1_buffer = exif_utils.GetApp1Buffer();
            size_t app1_size = exif_utils.GetApp1Length();
            size_t segment_size = app1_size + kJpegLengthSize;
            dst_addr = WriteTwoBytes(dst_addr, segment_size);

            // Copy the APP1 segment with the thumbnail.
            std::copy(app1_buffer, app1_buffer + app1_size, dst_addr);
            dst_addr += app1_size;
            break;
          }
          [[fallthrough]];
        }

        default:
          VLOGFID(1, frame_number)
              << "Write JPEG segment 0x" << std::hex << it->first;
          std::copy(it->second.begin(), it->second.end(), dst_addr);
          dst_addr += it->second.size();
      }
    }

    // Copy the JPEG image. Skip the SOI in the buffer.
    ScopedMapping jpeg_mapping(*context.jpeg_blob);
    std::copy(jpeg_mapping.plane(0).addr + kJpegMarkerSize,
              jpeg_mapping.plane(0).addr + context.jpeg_blob_size, dst_addr);
    dst_addr += (context.jpeg_blob_size - kJpegMarkerSize);

    InsertJpegBlobDescriptor(*context.client_requested_buffer.buffer,
                             (dst_addr - dst_start));
  }

  VLOGFID(1, frame_number) << "Return BLOB buffer to client";
  Camera3CaptureDescriptor blob_result(camera3_capture_result_t{
      .frame_number = static_cast<uint32_t>(frame_number),
      .num_output_buffers = 1,
      .output_buffers = &context.client_requested_buffer,
      .partial_result = 0,
  });
  result_callback_.Run(std::move(blob_result));
  request_contexts_.erase(frame_number);
}

bool ParseAppSectionsForTesting(
    base::span<uint8_t> blob,
    std::vector<uint8_t>* out_buffer,
    std::map<uint16_t, base::span<uint8_t>>* out_index) {
  return ParseAppSections(blob, out_buffer, out_index);
}

}  // namespace cros
