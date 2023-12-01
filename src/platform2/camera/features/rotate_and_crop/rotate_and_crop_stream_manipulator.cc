/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/rotate_and_crop/rotate_and_crop_stream_manipulator.h"

#include <drm_fourcc.h>
#include <libyuv.h>
#include <sync/sync.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <base/bits.h>
#include <base/containers/contains.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/strings/string_util.h>
#include <base/task/bind_post_task.h>
#include <brillo/key_value_store.h>

#include "common/camera_hal3_helpers.h"
#include "common/vendor_tag_manager.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/common.h"

namespace cros {

namespace {

class RotateAndCropVendorTag {
 public:
  static constexpr char kSectionName[] = "com.google.cros_rotate_and_crop";
  static constexpr char kHalAvailableModesTagName[] = "halAvailableModes";
  static constexpr uint32_t kHalAvailableModes =
      kCrosRotateAndCropVendorTagStart;
};

uint8_t DegreesToRotateAndCropMode(int crop_rotate_scale_degrees) {
  switch (crop_rotate_scale_degrees) {
    case CAMERA3_STREAM_ROTATION_0:
      return ANDROID_SCALER_ROTATE_AND_CROP_NONE;
    case CAMERA3_STREAM_ROTATION_90:
      return ANDROID_SCALER_ROTATE_AND_CROP_90;
    case CAMERA3_STREAM_ROTATION_180:
      return ANDROID_SCALER_ROTATE_AND_CROP_180;
    case CAMERA3_STREAM_ROTATION_270:
      return ANDROID_SCALER_ROTATE_AND_CROP_270;
    default:
      NOTREACHED();
      return ANDROID_SCALER_ROTATE_AND_CROP_NONE;
  }
}

libyuv::RotationMode RotateAndCropModeToLibyuvRotation(uint8_t rc_mode) {
  switch (rc_mode) {
    case ANDROID_SCALER_ROTATE_AND_CROP_NONE:
      return libyuv::kRotate0;
    case ANDROID_SCALER_ROTATE_AND_CROP_90:
      return libyuv::kRotate90;
    case ANDROID_SCALER_ROTATE_AND_CROP_180:
      return libyuv::kRotate180;
    case ANDROID_SCALER_ROTATE_AND_CROP_270:
      return libyuv::kRotate270;
    default:
      NOTREACHED();
      return libyuv::kRotate0;
  }
}

bool IsArcTBoard() {
  static bool value = []() {
    brillo::KeyValueStore store;
    if (!store.Load(base::FilePath("/etc/lsb-release"))) {
      LOGF(ERROR) << "Failed to read lsb-release";
      return false;
    }
    std::string board;
    if (!store.GetString("CHROMEOS_RELEASE_BOARD", &board)) {
      LOGF(ERROR) << "Failed to read board name";
      return false;
    }
    const std::string arc_t_suffix = "-arc-t";
    return board.size() > arc_t_suffix.size() &&
           board.substr(board.size() - arc_t_suffix.size()) == arc_t_suffix;
  }();
  return value;
}

}  // namespace

RotateAndCropStreamManipulator::RotateAndCropStreamManipulator(
    std::unique_ptr<StillCaptureProcessor> still_capture_processor)
    : still_capture_processor_(std::move(still_capture_processor)),
      thread_("RotateAndCropThread") {
  CHECK(thread_.Start());
}

RotateAndCropStreamManipulator::~RotateAndCropStreamManipulator() {
  thread_.Stop();
}

// static
bool RotateAndCropStreamManipulator::UpdateVendorTags(
    VendorTagManager& vendor_tag_manager) {
  if (!IsArcTBoard()) {
    return true;
  }
  if (!vendor_tag_manager.Add(RotateAndCropVendorTag::kHalAvailableModes,
                              RotateAndCropVendorTag::kSectionName,
                              RotateAndCropVendorTag::kHalAvailableModesTagName,
                              TYPE_BYTE)) {
    LOGF(ERROR) << "Failed to add vendor tag";
    return false;
  }
  return true;
}

// static
bool RotateAndCropStreamManipulator::UpdateStaticMetadata(
    android::CameraMetadata* static_info) {
  if (!IsArcTBoard()) {
    return true;
  }
  camera_metadata_entry_t entry =
      static_info->find(ANDROID_SCALER_AVAILABLE_ROTATE_AND_CROP_MODES);
  if (entry.count > 0) {
    DCHECK_EQ(entry.type, TYPE_BYTE);
    const std::vector<uint8_t> modes(entry.data.u8,
                                     entry.data.u8 + entry.count);
    if (static_info->update(RotateAndCropVendorTag::kHalAvailableModes,
                            modes.data(), modes.size()) != 0) {
      LOGF(ERROR) << "Failed to update "
                  << RotateAndCropVendorTag::kHalAvailableModesTagName;
      return false;
    }
  }
  constexpr uint8_t kClientAvailableRotateAndCropModes[] = {
      ANDROID_SCALER_ROTATE_AND_CROP_NONE, ANDROID_SCALER_ROTATE_AND_CROP_90,
      ANDROID_SCALER_ROTATE_AND_CROP_180,  ANDROID_SCALER_ROTATE_AND_CROP_270,
      ANDROID_SCALER_ROTATE_AND_CROP_AUTO,
  };
  if (static_info->update(ANDROID_SCALER_AVAILABLE_ROTATE_AND_CROP_MODES,
                          kClientAvailableRotateAndCropModes,
                          std::size(kClientAvailableRotateAndCropModes)) != 0) {
    LOGF(ERROR)
        << "Failed to update ANDROID_SCALER_AVAILABLE_ROTATE_AND_CROP_MODES";
    return false;
  }
  if (!AddListItemToMetadataTag(
          static_info, ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS,
          ANDROID_SCALER_AVAILABLE_ROTATE_AND_CROP_MODES)) {
    LOGF(ERROR)
        << "Failed to update ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS";
    return false;
  }
  if (!AddListItemToMetadataTag(static_info,
                                ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
                                ANDROID_SCALER_ROTATE_AND_CROP)) {
    LOGF(ERROR) << "Failed to update ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS";
    return false;
  }
  if (!AddListItemToMetadataTag(static_info,
                                ANDROID_REQUEST_AVAILABLE_RESULT_KEYS,
                                ANDROID_SCALER_ROTATE_AND_CROP)) {
    LOGF(ERROR) << "Failed to update ANDROID_REQUEST_AVAILABLE_RESULT_KEYS";
    return false;
  }

  return true;
}

bool RotateAndCropStreamManipulator::Initialize(
    const camera_metadata_t* static_info, Callbacks callbacks) {
  bool ret = false;
  thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(&RotateAndCropStreamManipulator::InitializeOnThread,
                     base::Unretained(this), static_info, callbacks),
      &ret);
  return ret;
}

bool RotateAndCropStreamManipulator::ConfigureStreams(
    Camera3StreamConfiguration* stream_config,
    const StreamEffectMap* stream_effects_map) {
  if (!IsArcTBoard()) {
    return true;
  }
  bool ret = false;
  thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(&RotateAndCropStreamManipulator::ConfigureStreamsOnThread,
                     base::Unretained(this), stream_config),
      &ret);
  return ret;
}

bool RotateAndCropStreamManipulator::OnConfiguredStreams(
    Camera3StreamConfiguration* stream_config) {
  if (!IsArcTBoard()) {
    return true;
  }
  bool ret = false;
  thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(
          &RotateAndCropStreamManipulator::OnConfiguredStreamsOnThread,
          base::Unretained(this), stream_config),
      &ret);
  return ret;
}

bool RotateAndCropStreamManipulator::ConstructDefaultRequestSettings(
    android::CameraMetadata* default_request_settings, int type) {
  if (default_request_settings->isEmpty() || !IsArcTBoard()) {
    return true;
  }
  const uint8_t rc_mode = ANDROID_SCALER_ROTATE_AND_CROP_AUTO;
  if (default_request_settings->update(ANDROID_SCALER_ROTATE_AND_CROP, &rc_mode,
                                       1) != 0) {
    LOGF(ERROR)
        << "Failed to update ANDROID_SCALER_ROTATE_AND_CROP to default request";
    return false;
  }
  return true;
}

bool RotateAndCropStreamManipulator::ProcessCaptureRequest(
    Camera3CaptureDescriptor* request) {
  if (!IsArcTBoard()) {
    return true;
  }
  bool ret = false;
  thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(
          &RotateAndCropStreamManipulator::ProcessCaptureRequestOnThread,
          base::Unretained(this), request),
      &ret);
  return ret;
}

bool RotateAndCropStreamManipulator::ProcessCaptureResult(
    Camera3CaptureDescriptor result) {
  if (!IsArcTBoard()) {
    callbacks_.result_callback.Run(std::move(result));
    return true;
  }
  bool ret = false;
  thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(
          &RotateAndCropStreamManipulator::ProcessCaptureResultOnThread,
          base::Unretained(this), std::move(result)),
      &ret);
  return ret;
}

void RotateAndCropStreamManipulator::Notify(camera3_notify_msg_t msg) {
  callbacks_.notify_callback.Run(msg);
}

bool RotateAndCropStreamManipulator::Flush() {
  return true;
}

bool RotateAndCropStreamManipulator::InitializeOnThread(
    const camera_metadata_t* static_info, Callbacks callbacks) {
  DCHECK(thread_.IsCurrentThread());

  callbacks_ = callbacks;

  if (!IsArcTBoard()) {
    LOGF(INFO) << "Disabled on non-ARC-T board";
    return true;
  }

  base::span<const uint8_t> modes = GetRoMetadataAsSpan<uint8_t>(
      static_info, RotateAndCropVendorTag::kHalAvailableModes);
  hal_available_rc_modes_ = base::flat_set<uint8_t>(modes.begin(), modes.end());
  if (VLOG_IS_ON(1)) {
    std::vector<std::string> mode_strs;
    std::transform(
        hal_available_rc_modes_.begin(), hal_available_rc_modes_.end(),
        std::back_inserter(mode_strs),
        [](uint8_t x) { return std::to_string(base::strict_cast<int>(x)); });
    VLOGF(1) << "HAL available rotate-and-crop modes: ["
             << base::JoinString(mode_strs, ", ") << "]";
  }

  std::optional<int32_t> partial_result_count =
      GetRoMetadata<int32_t>(static_info, ANDROID_REQUEST_PARTIAL_RESULT_COUNT);
  if (!partial_result_count.has_value()) {
    LOGF(WARNING)
        << "ANDROID_REQUEST_PARTIAL_RESULT_COUNT not found in static metadata";
    return false;
  }
  partial_result_count_ = base::checked_cast<uint32_t>(*partial_result_count);
  VLOGF(1) << "Partial result count: " << partial_result_count_;

  return true;
}

bool RotateAndCropStreamManipulator::ConfigureStreamsOnThread(
    Camera3StreamConfiguration* stream_config) {
  DCHECK(thread_.IsCurrentThread());

  ResetOnThread();

  DCHECK_GT(stream_config->num_streams(), 0);
  client_crs_degrees_ =
      stream_config->GetStreams()[0]->crop_rotate_scale_degrees;
  // Translate |crop_rotate_scale_degrees| to ROTATE_AND_CROP API if the HAL has
  // migrated to it.
  const int hal_crs_degrees = hal_available_rc_modes_.empty()
                                  ? client_crs_degrees_
                                  : CAMERA3_STREAM_ROTATION_0;
  for (auto* stream : stream_config->GetStreams()) {
    VLOGF(1) << "ConfigureStreams: " << GetDebugString(stream);
    if (stream->crop_rotate_scale_degrees != client_crs_degrees_) {
      LOGF(ERROR)
          << "crop_rotate_scale_degrees should be the same in every stream";
      return false;
    }
    stream->crop_rotate_scale_degrees = hal_crs_degrees;
    if (!blob_stream_ && stream->format == HAL_PIXEL_FORMAT_BLOB) {
      blob_stream_ = stream;
    }
  }
  if (blob_stream_) {
    still_capture_processor_->Initialize(
        blob_stream_,
        base::BindPostTask(
            thread_.task_runner(),
            base::BindRepeating(&RotateAndCropStreamManipulator::
                                    ReturnStillCaptureResultOnThread,
                                base::Unretained(this))));
    for (auto* stream : stream_config->GetStreams()) {
      if (stream->stream_type == CAMERA3_STREAM_OUTPUT &&
          (stream->format == HAL_PIXEL_FORMAT_YCbCr_420_888 ||
           stream->format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED) &&
          stream->width == blob_stream_->width &&
          stream->height == blob_stream_->height) {
        yuv_stream_for_blob_ = stream;
      }
    }
    if (!yuv_stream_for_blob_) {
      yuv_stream_for_blob_owned_ = camera3_stream_t{
          .width = blob_stream_->width,
          .height = blob_stream_->height,
          .format = HAL_PIXEL_FORMAT_YCbCr_420_888,
          .usage = GRALLOC_USAGE_SW_READ_OFTEN,
          .crop_rotate_scale_degrees = hal_crs_degrees,
      };
      yuv_stream_for_blob_ = &yuv_stream_for_blob_owned_.value();
      stream_config->AppendStream(&yuv_stream_for_blob_owned_.value());
    }
  }

  return true;
}

bool RotateAndCropStreamManipulator::OnConfiguredStreamsOnThread(
    Camera3StreamConfiguration* stream_config) {
  DCHECK(thread_.IsCurrentThread());

  // Restore client config.
  for (camera3_stream_t* stream : stream_config->GetStreams()) {
    VLOGF(1) << "OnConfiguredStreams: " << GetDebugString(stream);
    stream->crop_rotate_scale_degrees = client_crs_degrees_;
  }
  if (yuv_stream_for_blob_) {
    yuv_buffer_pool_ =
        std::make_unique<CameraBufferPool>(CameraBufferPool::Options{
            .width = yuv_stream_for_blob_->width,
            .height = yuv_stream_for_blob_->height,
            .format =
                base::checked_cast<uint32_t>(yuv_stream_for_blob_->format),
            .usage = yuv_stream_for_blob_->usage,
            .max_num_buffers = yuv_stream_for_blob_->max_buffers,
        });
    if (yuv_stream_for_blob_owned_) {
      if (!stream_config->RemoveStream(yuv_stream_for_blob_)) {
        LOGF(ERROR) << "Failed to remove appended YUV stream";
        return false;
      }
    }
  }
  return true;
}

bool RotateAndCropStreamManipulator::ProcessCaptureRequestOnThread(
    Camera3CaptureDescriptor* request) {
  DCHECK(thread_.IsCurrentThread());

  uint8_t rc_mode_from_crs_degrees =
      DegreesToRotateAndCropMode(client_crs_degrees_);
  auto [ctx_it, is_inserted] = capture_contexts_.insert(
      std::make_pair(request->frame_number(),
                     CaptureContext{
                         .client_rc_mode = rc_mode_from_crs_degrees,
                         .hal_rc_mode = rc_mode_from_crs_degrees,
                         .num_pending_buffers = request->num_output_buffers(),
                         .metadata_received = false,
                     }));
  DCHECK(is_inserted);
  CaptureContext& ctx = ctx_it->second;

  // Check if the client uses ROTATE_AND_CROP API.
  base::span<const uint8_t> rc_mode =
      request->GetMetadata<uint8_t>(ANDROID_SCALER_ROTATE_AND_CROP);
  if (!rc_mode.empty() && rc_mode[0] != ANDROID_SCALER_ROTATE_AND_CROP_AUTO) {
    ctx.client_rc_mode = rc_mode[0];
    ctx.hal_rc_mode = ANDROID_SCALER_ROTATE_AND_CROP_NONE;
  }

  // Check if the HAL has migrated to ROTATE_AND_CROP API and supports the
  // client requested rotation.
  if (!hal_available_rc_modes_.empty()) {
    ctx.hal_rc_mode =
        base::Contains(hal_available_rc_modes_, ctx.client_rc_mode)
            ? ctx.client_rc_mode
            : ANDROID_SCALER_ROTATE_AND_CROP_NONE;
  }

  if (!request->UpdateMetadata<uint8_t>(
          ANDROID_SCALER_ROTATE_AND_CROP,
          std::array<uint8_t, 1>{ctx.hal_rc_mode})) {
    LOGF(ERROR) << "Failed to update ANDROID_SCALER_ROTATE_AND_CROP in request "
                << request->frame_number();
    return false;
  }

  // Bypass the request when we don't need to do rotation.
  if (ctx.client_rc_mode == ctx.hal_rc_mode) {
    return true;
  }

  // Process still capture.
  bool has_yuv = false;
  for (const auto& b : request->GetOutputBuffers()) {
    if (b.stream() == blob_stream_) {
      ctx.has_pending_blob = true;
      still_capture_processor_->QueuePendingOutputBuffer(
          request->frame_number(), b.raw_buffer(), *request);
    } else if (b.stream() == yuv_stream_for_blob_) {
      has_yuv = true;
    }
  }
  if (ctx.has_pending_blob && !has_yuv) {
    ctx.yuv_buffer = yuv_buffer_pool_->RequestBuffer();
    if (!ctx.yuv_buffer) {
      LOGF(ERROR) << "Failed to allocate buffer for frame "
                  << request->frame_number();
      return false;
    }
    request->AppendOutputBuffer(Camera3StreamBuffer::MakeRequestOutput({
        .stream = yuv_stream_for_blob_,
        .buffer = ctx.yuv_buffer->handle(),
        .status = CAMERA3_BUFFER_STATUS_OK,
        .acquire_fence = -1,
        .release_fence = -1,
    }));
    ++ctx.num_pending_buffers;
    ctx.yuv_stream_appended = true;
  }

  return true;
}

bool RotateAndCropStreamManipulator::ProcessCaptureResultOnThread(
    Camera3CaptureDescriptor result) {
  DCHECK(thread_.IsCurrentThread());

  auto ctx_it = capture_contexts_.find(result.frame_number());
  DCHECK(ctx_it != capture_contexts_.end());
  CaptureContext& ctx = ctx_it->second;

  DCHECK_GE(ctx.num_pending_buffers, result.num_output_buffers());
  ctx.num_pending_buffers -= result.num_output_buffers();
  ctx.metadata_received |= result.partial_result() == partial_result_count_;

  base::ScopedClosureRunner ctx_deleter;
  if (ctx.num_pending_buffers == 0 && ctx.metadata_received &&
      !ctx.has_pending_blob) {
    ctx_deleter.ReplaceClosure(base::BindOnce(
        [](decltype(capture_contexts_)* contexts, uint32_t frame_number) {
          contexts->erase(frame_number);
        },
        &capture_contexts_, result.frame_number()));
  }

  // Bypass the result when we don't need to do rotation.
  if (ctx.client_rc_mode == ctx.hal_rc_mode) {
    callbacks_.result_callback.Run(std::move(result));
    return true;
  }
  DCHECK_EQ(ctx.hal_rc_mode, ANDROID_SCALER_ROTATE_AND_CROP_NONE);

  for (auto& b : result.AcquireOutputBuffers()) {
    if (b.stream() == blob_stream_) {
      still_capture_processor_->QueuePendingAppsSegments(
          result.frame_number(), *b.buffer(),
          base::ScopedFD(b.take_release_fence()));
      continue;
    }
    if (b.stream()->stream_type == CAMERA3_STREAM_OUTPUT &&
        (b.stream()->format == HAL_PIXEL_FORMAT_YCbCr_420_888 ||
         b.stream()->format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED)) {
      if (b.status() == CAMERA3_BUFFER_STATUS_OK) {
        if (!RotateAndCropOnThread(*b.buffer(),
                                   base::ScopedFD(b.take_release_fence()),
                                   ctx.client_rc_mode)) {
          b.mutable_raw_buffer().status = CAMERA3_BUFFER_STATUS_ERROR;
        }
      }
      if (b.stream() == yuv_stream_for_blob_) {
        if (ctx.has_pending_blob) {
          // TODO(kamesan): Fail the still capture properly if YUV image fails.
          CHECK_EQ(b.status(), CAMERA3_BUFFER_STATUS_OK);
          still_capture_processor_->QueuePendingYuvImage(
              result.frame_number(), *b.buffer(), base::ScopedFD());
        }
        if (ctx.yuv_stream_appended) {
          continue;
        }
      }
    }
    result.AppendOutputBuffer(std::move(b));
  }

  base::span<const uint8_t> rc_mode =
      result.GetMetadata<uint8_t>(ANDROID_SCALER_ROTATE_AND_CROP);
  if (!rc_mode.empty()) {
    if (rc_mode[0] != ctx.hal_rc_mode) {
      LOGF(WARNING)
          << "Incorrect ANDROID_SCALER_ROTATE_AND_CROP received in result "
          << result.frame_number() << "; expected " << ctx.hal_rc_mode
          << ", got " << rc_mode[0];
    }
    if (ctx.client_rc_mode != rc_mode[0] &&
        !result.UpdateMetadata<uint8_t>(
            ANDROID_SCALER_ROTATE_AND_CROP,
            std::array<uint8_t, 1>{ctx.client_rc_mode})) {
      LOGF(ERROR)
          << "Failed to update ANDROID_SCALER_ROTATE_AND_CROP in result "
          << result.frame_number();
    }
  }
  // TODO(kamesan): Some metadata need to be mapped to the rotated image
  // coordinates.

  callbacks_.result_callback.Run(std::move(result));
  return true;
}

void RotateAndCropStreamManipulator::ResetOnThread() {
  DCHECK(thread_.IsCurrentThread());

  still_capture_processor_->Reset();
  client_crs_degrees_ = CAMERA3_STREAM_ROTATION_0;
  blob_stream_ = nullptr;
  yuv_stream_for_blob_owned_ = std::nullopt;
  yuv_stream_for_blob_ = nullptr;
  yuv_buffer_pool_.reset();
  buffer1_.Reset();
  buffer2_.Reset();
  capture_contexts_.clear();
}

void RotateAndCropStreamManipulator::ReturnStillCaptureResultOnThread(
    Camera3CaptureDescriptor result) {
  DCHECK(thread_.IsCurrentThread());

  auto ctx_it = capture_contexts_.find(result.frame_number());
  DCHECK(ctx_it != capture_contexts_.end());
  CaptureContext& ctx = ctx_it->second;

  ctx.yuv_buffer = std::nullopt;

  CHECK(ctx.has_pending_blob);
  ctx.has_pending_blob = false;
  if (ctx.num_pending_buffers == 0 && ctx.metadata_received &&
      !ctx.has_pending_blob) {
    capture_contexts_.erase(result.frame_number());
  }

  callbacks_.result_callback.Run(std::move(result));
}

bool RotateAndCropStreamManipulator::RotateAndCropOnThread(
    buffer_handle_t buffer, base::ScopedFD release_fence, uint8_t rc_mode) {
  DCHECK(thread_.IsCurrentThread());

  if (rc_mode == ANDROID_SCALER_ROTATE_AND_CROP_NONE) {
    return true;
  }

  if (release_fence.is_valid()) {
    constexpr int kSyncWaitTimeoutMs = 300;
    if (sync_wait(release_fence.get(), kSyncWaitTimeoutMs) != 0) {
      LOGF(ERROR) << "sync_wait() timed out";
      return false;
    }
  }

  ScopedMapping mapping(buffer);
  if (mapping.drm_format() != DRM_FORMAT_NV12) {
    LOGF(ERROR) << "Unsupported DRM format: " << mapping.drm_format();
    return false;
  }
  if (mapping.width() < mapping.height()) {
    LOGF(ERROR) << "Portrait image is not supported: " << mapping.width() << "x"
                << mapping.height();
    return false;
  }

  // TODO(kamesan): Offload the conversions to GPU with GpuImageProcessor.

  uint32_t src_width = mapping.width();
  uint32_t src_height = mapping.height();
  uint32_t src_offset = 0;
  uint32_t dst_width = src_width;
  uint32_t dst_height = src_height;
  if (rc_mode == ANDROID_SCALER_ROTATE_AND_CROP_90 ||
      rc_mode == ANDROID_SCALER_ROTATE_AND_CROP_270) {
    src_width = base::bits::AlignUp(
        mapping.height() * mapping.height() / mapping.width(), 2u);
    src_height = mapping.height();
    src_offset = base::bits::AlignDown((mapping.width() - src_width) / 2, 2u);
    dst_width = src_height;
    dst_height = src_width;
  }
  buffer1_.SetFormat(dst_width, dst_height, DRM_FORMAT_YUV420);
  int ret = libyuv::NV12ToI420Rotate(
      mapping.plane(0).addr + src_offset, mapping.plane(0).stride,
      mapping.plane(1).addr + src_offset, mapping.plane(1).stride,
      buffer1_.plane(0).addr, buffer1_.plane(0).stride, buffer1_.plane(1).addr,
      buffer1_.plane(1).stride, buffer1_.plane(2).addr,
      buffer1_.plane(2).stride, src_width, src_height,
      RotateAndCropModeToLibyuvRotation(rc_mode));
  if (ret != 0) {
    LOGF(ERROR) << "libyuv::NV12ToI420Rotate() failed: " << ret;
    return false;
  }

  ResizableCpuBuffer* final_i420 = &buffer1_;
  if (rc_mode == ANDROID_SCALER_ROTATE_AND_CROP_90 ||
      rc_mode == ANDROID_SCALER_ROTATE_AND_CROP_270) {
    buffer2_.SetFormat(mapping.width(), mapping.height(), DRM_FORMAT_YUV420);
    ret = libyuv::I420Scale(buffer1_.plane(0).addr, buffer1_.plane(0).stride,
                            buffer1_.plane(1).addr, buffer1_.plane(1).stride,
                            buffer1_.plane(2).addr, buffer1_.plane(2).stride,
                            dst_width, dst_height, buffer2_.plane(0).addr,
                            buffer2_.plane(0).stride, buffer2_.plane(1).addr,
                            buffer2_.plane(1).stride, buffer2_.plane(2).addr,
                            buffer2_.plane(2).stride, mapping.width(),
                            mapping.height(), libyuv::kFilterBilinear);
    if (ret != 0) {
      LOGF(ERROR) << "libyuv::I420Scale() failed: " << ret;
      return false;
    }
    final_i420 = &buffer2_;
  }

  ret = libyuv::I420ToNV12(
      final_i420->plane(0).addr, final_i420->plane(0).stride,
      final_i420->plane(1).addr, final_i420->plane(1).stride,
      final_i420->plane(2).addr, final_i420->plane(2).stride,
      mapping.plane(0).addr, mapping.plane(0).stride, mapping.plane(1).addr,
      mapping.plane(1).stride, mapping.width(), mapping.height());
  if (ret != 0) {
    LOGF(ERROR) << "libyuv::I420ToNV12() failed: " << ret;
    return false;
  }

  return true;
}

}  // namespace cros
