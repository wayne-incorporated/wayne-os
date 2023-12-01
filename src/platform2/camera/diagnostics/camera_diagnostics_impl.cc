// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "camera/diagnostics/camera_diagnostics_impl.h"

#include <memory>
#include <utility>

#include <hardware/gralloc.h>

#include "cros-camera/common.h"
#include "cutils/native_handle.h"

namespace cros {

CameraDiagnosticsImpl::CameraDiagnosticsImpl()
    : analysis_result_(
          static_cast<uint32_t>(mojom::DiagnosticsResult::UNKNOWN)),
      yuv_analysis_enabled_(false),
      privacy_shutter_detector_(PrivacyShutterDetector::New()) {}

void CameraDiagnosticsImpl::SetYuvAnalysisEnabled(bool state) {
  if (!state) {
    VLOGF(1) << "YUV analysis is disabled";
    analysis_result_ = static_cast<uint32_t>(mojom::DiagnosticsResult::UNKNOWN);
  }
  // TODO(b/279844311): Register YUVFrameProviders with camera diagnostics
  // service to notify them of updates.
  LOGF(INFO) << "Updated YUV state analysis is: " << state;
  yuv_analysis_enabled_ = state;
}

void CameraDiagnosticsImpl::GetYuvAnalysisEnabled(
    GetYuvAnalysisEnabledCallback callback) {
  std::move(callback).Run(yuv_analysis_enabled_);
}

void CameraDiagnosticsImpl::AnalyzeYuvFrame(
    mojom::CameraDiagnosticsFramePtr buffer, AnalyzeYuvFrameCallback callback) {
  const uint32_t kSize = buffer->data_size;
  uint8_t temp_buffer[kSize];
  uint32_t num_bytes = kSize;
  buffer->data_handle->ReadData(temp_buffer, &num_bytes,
                                MOJO_READ_DATA_FLAG_NONE);

  uint32_t y_size = buffer->width * buffer->height;
  uint8_t* nv12_y_data = temp_buffer;
  uint8_t* nv12_uv_data = nv12_y_data + y_size;

  // TODO(rabbim): Remove this ScopedBuffer allocation and redundant copy part
  // once privacy shutter interface is modified.

  ScopedBufferHandle target_handle = CameraBufferManager::AllocateScopedBuffer(
      buffer->width, buffer->height, HAL_PIXEL_FORMAT_YCbCr_420_888,
      GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN);
  buffer_handle_t target_buffer = *target_handle;
  auto mapping_target = ScopedMapping(target_buffer);

  memcpy(mapping_target.plane(0).addr, nv12_y_data,
         mapping_target.plane(0).size);
  memcpy(mapping_target.plane(1).addr, nv12_uv_data,
         mapping_target.plane(1).size);

  bool isShutterClosed;
  bool ret = privacy_shutter_detector_->DetectPrivacyShutterFromHandle(
      target_buffer, &isShutterClosed);

  if (!ret) {
    std::move(callback).Run(mojom::Response::ANALYSIS_FAILED);
    LOGF(ERROR) << "Failed to run privacy shutter detector";
    return;
  }

  if (isShutterClosed) {
    analysis_result_ |=
        static_cast<uint32_t>(mojom::DiagnosticsResult::PRIVACY_SHUTTER_ON);
  }
  std::move(callback).Run(mojom::Response::FRAME_PROCESS_SUCCESSFUL);
}

void CameraDiagnosticsImpl::GetDiagnosticsResult(
    GetDiagnosticsResultCallback callback) {
  VLOGF(1) << "Provide diagnostics result";
  std::move(callback).Run(std::move(analysis_result_));
}

}  // namespace cros
