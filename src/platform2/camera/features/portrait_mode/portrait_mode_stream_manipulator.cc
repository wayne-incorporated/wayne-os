/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/portrait_mode/portrait_mode_stream_manipulator.h"

#include <cstdint>
#include <iterator>
#include <utility>

#include "common/camera_buffer_handle.h"
#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/common.h"
#include "features/portrait_mode/tracing.h"

//
// PortraitModeStreamManipulator implementations.
//

namespace cros {

namespace {

bool CanEnablePortraitMode(const camera_metadata_t* metadata) {
  base::span<const uint8_t> available_caps = GetRoMetadataAsSpan<uint8_t>(
      metadata, ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
  if (std::find(available_caps.begin(), available_caps.end(),
                ANDROID_REQUEST_AVAILABLE_CAPABILITIES_YUV_REPROCESSING) ==
      available_caps.end()) {
    return false;
  }
  return true;
}

}  // namespace

PortraitModeStreamManipulator::PortraitModeStreamManipulator(
    CameraMojoChannelManagerToken* mojo_manager_token)
    : mojo_manager_token_(mojo_manager_token) {}

PortraitModeStreamManipulator::~PortraitModeStreamManipulator() {}

// static
bool PortraitModeStreamManipulator::UpdateVendorTags(
    VendorTagManager& vendor_tag_manager) {
  if (!vendor_tag_manager.Add(kPortraitModeVendorKey,
                              kPortraitModeVendorTagSectionName,
                              kPortraitModeVendorTagName, TYPE_BYTE) ||
      !vendor_tag_manager.Add(kPortraitModeSegmentationResultVendorKey,
                              kPortraitModeVendorTagSectionName,
                              kPortraitModeResultVendorTagName, TYPE_BYTE)) {
    LOGF(ERROR) << "Failed to add the vendor tag for CrOS Portrait Mode";
    return false;
  }
  return true;
}

// static
bool PortraitModeStreamManipulator::UpdateStaticMetadata(
    android::CameraMetadata* static_info) {
  // TODO(julianachang): We don't need to set Portrait Mode tags to static
  // metadata, but CCA won't enable Portrait Mode if we remove this part. Will
  // modify this after adding PortraitModeStreamManipulator.
  const camera_metadata_t* locked_metadata = static_info->getAndLock();
  if (!CanEnablePortraitMode(locked_metadata)) {
    static_info->unlock(locked_metadata);
    return true;
  }
  static_info->unlock(locked_metadata);
  uint8_t update_portrait_vendor_key = 1;
  if (static_info->update(kPortraitModeVendorKey, &update_portrait_vendor_key,
                          1) != 0) {
    LOGF(ERROR) << "Failed to update kPortraitModeVendorKey to static metadata";
    return false;
  }
  return true;
}

bool PortraitModeStreamManipulator::Initialize(
    const camera_metadata_t* static_info,
    StreamManipulator::Callbacks callbacks) {
  TRACE_PORTRAIT_MODE();

  callbacks_ = std::move(callbacks);
  if (!CanEnablePortraitMode(static_info)) {
    return true;
  }

  // Initialize Portrait Mode effect.
  portrait_mode_ = std::make_unique<PortraitModeEffect>();
  if (portrait_mode_->Initialize(mojo_manager_token_) != 0) {
    LOGF(ERROR) << "Failed to initialize Portrait Mode effect";
    return false;
  }
  return true;
}

bool PortraitModeStreamManipulator::ConfigureStreams(
    Camera3StreamConfiguration* stream_config,
    const StreamEffectMap* stream_effect_map) {
  return true;
}

bool PortraitModeStreamManipulator::OnConfiguredStreams(
    Camera3StreamConfiguration* stream_config) {
  return true;
}

bool PortraitModeStreamManipulator::ConstructDefaultRequestSettings(
    android::CameraMetadata* default_request_settings, int type) {
  return true;
}

bool PortraitModeStreamManipulator::ProcessCaptureRequest(
    Camera3CaptureDescriptor* request) {
  TRACE_PORTRAIT_MODE("frame_number", request->frame_number());

  // Skip portrait request when no input buffer.
  if (!request->has_input_buffer() || request->num_output_buffers() == 0) {
    return true;
  }
  // Check if the metadata contains Portrait Mode tag with value equal to true.
  base::span<const uint8_t> entry =
      request->GetMetadata<uint8_t>(kPortraitModeVendorKey);
  if (entry.empty()) {
    LOGF(INFO) << "Cannot find portrait tag in metadata";
    return true;
  }
  bool can_process_portrait_mode = entry[0] != 0;
  // Check if there's a pending Portrait Mode result to be set.
  if (reprocess_context_) {
    LOGF(ERROR)
        << "Portrait Mode requested when waiting for the previuos result";
    return false;
  }

  LOGF(INFO) << "Apply portrait reprocessing on input buffer";
  const camera3_stream_t* input_stream = request->GetInputBuffer()->stream();
  const camera3_stream_t* output_stream =
      request->GetOutputBuffers()[0].stream();
  // Here we assume reprocessing effects can provide only one output of the
  // same size and format as that of input. Invoke HAL reprocessing if more
  // outputs, scaling and/or format conversion are required since ISP
  // may provide hardware acceleration for these operations.
  bool need_hal_reprocessing =
      (request->num_output_buffers() != 1) ||
      (input_stream->width != output_stream->width) ||
      (input_stream->height != output_stream->height) ||
      (input_stream->format != output_stream->format);
  buffer_handle_t output_buffer = *request->GetOutputBuffers()[0].buffer();
  ScopedBufferHandle scoped_output_handle;
  if (need_hal_reprocessing) {
    scoped_output_handle = CameraBufferManager::AllocateScopedBuffer(
        input_stream->width, input_stream->height,
        HAL_PIXEL_FORMAT_YCbCr_420_888,
        GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN);
    if (!scoped_output_handle) {
      LOGF(ERROR) << "Failed to allocate reprocessing output buffer "
                  << request->frame_number();
      return false;
    }
    output_buffer = *scoped_output_handle;
  }
  ScopedMapping output_mapping(output_buffer);
  if (!output_mapping.is_valid()) {
    LOGF(ERROR) << "Failed to map reprocessing output buffer";
    return false;
  }
  buffer_handle_t input_buffer = *request->GetInputBuffer()->buffer();
  ScopedMapping input_mapping(input_buffer);
  if (!input_mapping.is_valid()) {
    LOGF(ERROR) << "Failed to map reprocessing input buffer";
    return false;
  }
  uint32_t orientation = 0;
  if (request->HasMetadata(ANDROID_JPEG_ORIENTATION)) {
    orientation = request->GetMetadata<int32_t>(ANDROID_JPEG_ORIENTATION)[0];
  }
  SegmentationResult seg_result = SegmentationResult::kUnknown;
  if (portrait_mode_->ReprocessRequest(can_process_portrait_mode, input_buffer,
                                       orientation, &seg_result,
                                       output_buffer) != 0) {
    LOGF(ERROR) << "Failed to apply Portrait Mode effect";
    return false;
  }
  if (need_hal_reprocessing) {
    // Replace the input buffer with reprocessing output buffer.
    std::optional<Camera3StreamBuffer> in_buf = request->AcquireInputBuffer();
    DCHECK_NE(scoped_output_handle, nullptr);
    DCHECK_NE(*in_buf->buffer(), nullptr);
    {
      base::AutoLock lock(reprocess_context_lock_);
      reprocess_context_ = ReprocessContext{
          .frame_number = request->frame_number(),
          .original_input_buffer = std::move(*in_buf->buffer()),
          .replaced_input_buffer = std::move(scoped_output_handle),
          .segmentation_result = seg_result,
      };
      in_buf->mutable_raw_buffer().buffer =
          reprocess_context_->replaced_input_buffer.get();
      request->SetInputBuffer(std::move(in_buf.value()));
    }
  }
  return true;
}

bool PortraitModeStreamManipulator::ProcessCaptureResult(
    Camera3CaptureDescriptor result) {
  TRACE_PORTRAIT_MODE("frame_number", result.frame_number());

  base::AutoLock lock(reprocess_context_lock_);
  if (reprocess_context_ &&
      reprocess_context_->frame_number == result.frame_number()) {
    const Camera3StreamBuffer* input_buffer = result.GetInputBuffer();
    // Restore original input buffer.
    if (reprocess_context_->replaced_input_buffer && input_buffer) {
      DCHECK_EQ(*input_buffer->buffer(),
                *reprocess_context_->replaced_input_buffer);
      std::optional<Camera3StreamBuffer> in_buf = result.AcquireInputBuffer();
      *in_buf->mutable_raw_buffer().buffer =
          reprocess_context_->original_input_buffer;
      result.SetInputBuffer(std::move(in_buf.value()));
      reprocess_context_->original_input_buffer = nullptr;
      reprocess_context_->replaced_input_buffer.reset();
    }
    // Fill Portrait Mode segmentation result in metadata.
    if (reprocess_context_->segmentation_result.has_value() &&
        result.has_metadata()) {
      SegmentationResult seg_result = *reprocess_context_->segmentation_result;
      if (seg_result == SegmentationResult::kUnknown ||
          !result.UpdateMetadata<uint8_t>(
              kPortraitModeSegmentationResultVendorKey,
              std::array<uint8_t, 1>{static_cast<unsigned char>(seg_result)})) {
        LOGF(ERROR) << "Cannot update kPortraitModeSegmentationResultVendorKey "
                       "in result "
                    << result.frame_number();
      }
      reprocess_context_->segmentation_result.reset();
    }
    if (!reprocess_context_->replaced_input_buffer &&
        !reprocess_context_->segmentation_result.has_value()) {
      reprocess_context_.reset();
    }
  }
  callbacks_.result_callback.Run(std::move(result));
  return true;
}

void PortraitModeStreamManipulator::Notify(camera3_notify_msg_t msg) {
  callbacks_.notify_callback.Run(std::move(msg));
}

bool PortraitModeStreamManipulator::Flush() {
  return true;
}

}  // namespace cros
