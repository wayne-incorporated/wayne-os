/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/gcam_ae/gcam_ae_device_adapter_ipu6.h"

#include <optional>
#include <utility>

#include <sync/sync.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/common.h"
#include "features/third_party/intel/intel_vendor_metadata_tags.h"

namespace cros {

namespace {

// IPU6 uses fixed white level of 32000 (for 15-bit value). Scaling the value
// to 8-bit gives us 249.
constexpr int kIpu6WhiteLevel = 249;

}  // namespace

GcamAeDeviceAdapterIpu6::GcamAeDeviceAdapterIpu6()
    : gcam_ae_(GcamAe::CreateInstance()) {}

bool GcamAeDeviceAdapterIpu6::WriteRequestParameters(
    Camera3CaptureDescriptor* request) {
  std::array<uint8_t, 1> rgbs_grid_enable = {
      INTEL_VENDOR_CAMERA_CALLBACK_RGBS_TRUE};
  if (!request->UpdateMetadata<uint8_t>(INTEL_VENDOR_CAMERA_CALLBACK_RGBS,
                                        rgbs_grid_enable)) {
    LOGF(ERROR) << "Cannot enable INTEL_VENDOR_CAMERA_CALLBACK_RGBS in "
                   "request metadta";
    return false;
  }
  return true;
}

bool GcamAeDeviceAdapterIpu6::SetExposureTargetVendorTag(
    Camera3CaptureDescriptor* request, float exposure_target) {
  // Gcam AE computes TET using ms, but Intel IPU6 HAL expects exposure time in
  // ns.
  constexpr float kNsPerMs = 1.0e6f;
  std::array<int64_t, 1> tet = {
      static_cast<int64_t>(exposure_target * kNsPerMs)};
  DVLOGFID(1, request->frame_number()) << "tet=" << tet[0];
  if (!request->UpdateMetadata<int64_t>(
          INTEL_VENDOR_CAMERA_TOTAL_EXPOSURE_TARGET, tet)) {
    LOGFID(ERROR, request->frame_number())
        << "Cannot set INTEL_VENDOR_CAMERA_TOTAL_EXPOSURE_TARGET to " << tet[0]
        << " in request metadata";
    return false;
  }
  return true;
}

bool GcamAeDeviceAdapterIpu6::ExtractAeStats(Camera3CaptureDescriptor* result,
                                             MetadataLogger* metadata_logger_) {
  base::span<const int32_t> rgbs_grid_size =
      result->GetMetadata<int32_t>(INTEL_VENDOR_CAMERA_RGBS_GRID_SIZE);
  if (rgbs_grid_size.empty()) {
    VLOGF(2) << "Cannot get INTEL_VENDOR_CAMERA_RGBS_GRID_SIZE";
    return false;
  }
  base::span<const uint8_t> ae_stats_shading_correction =
      result->GetMetadata<uint8_t>(INTEL_VENDOR_CAMERA_SHADING_CORRECTION);
  if (ae_stats_shading_correction.empty()) {
    VLOGF(2) << "Cannot get INTEL_VENDOR_CAMERA_SHADING_CORRECTION";
    return false;
  }
  base::span<const uint8_t> ae_stats_blocks =
      result->GetMetadata<uint8_t>(INTEL_VENDOR_CAMERA_RGBS_STATS_BLOCKS);
  if (ae_stats_blocks.empty()) {
    VLOGF(2) << "Cannot get INTEL_VENDOR_CAMERA_RGBS_STATS_BLOCKS";
    return false;
  }

  int grid_width = rgbs_grid_size[0];
  int grid_height = rgbs_grid_size[1];
  if (VLOG_IS_ON(2)) {
    VLOGF(2) << "ae_stats_grid_width=" << grid_width;
    VLOGF(2) << "ae_stats_grid_height=" << grid_height;
    VLOGF(2) << "ae_stats_shading_correction="
             << (ae_stats_shading_correction[0] ==
                 INTEL_VENDOR_CAMERA_SHADING_CORRECTION_TRUE);
    VLOGF(2) << "ae_stats_blocks.size()=" << ae_stats_blocks.size();
    for (int y = 0; y < grid_height; ++y) {
      for (int x = 0; x < grid_width; ++x) {
        int base = (y * grid_width + x) * 5;
        int avg_gr = ae_stats_blocks[base];
        int avg_r = ae_stats_blocks[base + 1];
        int avg_b = ae_stats_blocks[base + 2];
        int avg_gb = ae_stats_blocks[base + 3];
        int sat = ae_stats_blocks[base + 4];
        VLOGF(2) << "block (" << x << "," << y
                 << ") sat=" << static_cast<float>(sat) / 255.0
                 << ", avg_gr=" << avg_gr << ", avg_r=" << avg_r
                 << ", avg_b=" << avg_b << ", avg_gb=" << avg_gb;
      }
    }
  }

  // We should create the entry only when there's valid AE stats, so that when
  // HasAeStats() returns true there's indeed valid AE stats.
  std::optional<AeStatsEntry*> entry =
      GetAeStatsEntry(result->frame_number(), /*create_entry=*/true);

  (*entry)->ae_stats.white_level = kIpu6WhiteLevel;
  (*entry)->ae_stats.grid_width = grid_width;
  (*entry)->ae_stats.grid_height = grid_height;
  int num_grid_blocks = grid_width * grid_height;
  for (int i = 0; i < num_grid_blocks; ++i) {
    int base = i * 5;
    AeStatsGridBlockIntelIpu6& block = (*entry)->ae_stats.grid_blocks[i];
    block.avg_gr = ae_stats_blocks[base];
    block.avg_r = ae_stats_blocks[base + 1];
    block.avg_b = ae_stats_blocks[base + 2];
    block.avg_gb = ae_stats_blocks[base + 3];
    block.sat = ae_stats_blocks[base + 4];
  }

  base::span<const int64_t> tet_range = result->GetMetadata<int64_t>(
      INTEL_VENDOR_CAMERA_TOTAL_EXPOSURE_TARGET_RANGE);
  if (tet_range.empty()) {
    DVLOGF(2) << "Cannot get INTEL_VENDOR_CAMERA_TOTAL_EXPOSURE_TARGET_RANGE";
  } else {
    // Intel camera HAL reports the TET range in us, while Gcam AE expects the
    // TET range in ms.
    constexpr float kUsInMs = 1000.0f;
    (*entry)->tet_range = {static_cast<float>(tet_range[0]) / kUsInMs,
                           static_cast<float>(tet_range[1]) / kUsInMs};
  }

  if (metadata_logger_) {
    metadata_logger_->Log(result->frame_number(), kTagWhiteLevel,
                          kIpu6WhiteLevel);
    metadata_logger_->Log(result->frame_number(), kTagIpu6RgbsStatsGridWidth,
                          grid_width);
    metadata_logger_->Log(result->frame_number(), kTagIpu6RgbsStatsGridHeight,
                          grid_height);
    metadata_logger_->Log(result->frame_number(),
                          kTagIpu6RgbsStatsShadingCorrection,
                          ae_stats_shading_correction[0]);
    metadata_logger_->Log(result->frame_number(), kTagIpu6RgbsStatsBlocks,
                          ae_stats_blocks);
    if (!tet_range.empty()) {
      metadata_logger_->Log(result->frame_number(), kTagIpu6TetRange,
                            tet_range);
    }
  }

  return true;
}

bool GcamAeDeviceAdapterIpu6::HasAeStats(int frame_number) {
  return GetAeStatsEntry(frame_number).has_value();
}

AeParameters GcamAeDeviceAdapterIpu6::ComputeAeParameters(
    int frame_number,
    const AeFrameInfo& frame_info,
    const Range<float>& device_tet_range,
    float max_hdr_ratio) {
  AeParameters ae_parameters = {.tet_range = device_tet_range};
  AeFrameMetadata ae_metadata{
      .actual_analog_gain = frame_info.analog_gain,
      .applied_digital_gain = frame_info.digital_gain,
      .actual_exposure_time_ms = frame_info.exposure_time_ms,
      .sensor_sensitivity = frame_info.estimated_sensor_sensitivity,
      .faces = *frame_info.faces,
      .exposure_compensation = frame_info.base_ae_compensation_log2 +
                               frame_info.client_ae_compensation_log2,
  };

  VLOGF(1) << "Running Gcam AE "
           << " [" << frame_number << "]"
           << " ae_stats_input="
           << static_cast<int>(frame_info.ae_stats_input_mode)
           << " exposure_time=" << ae_metadata.actual_exposure_time_ms
           << " analog_gain=" << ae_metadata.actual_analog_gain
           << " digital_gain=" << ae_metadata.applied_digital_gain
           << " num_faces=" << ae_metadata.faces.size()
           << " exposure_compensation=" << ae_metadata.exposure_compensation;

  AeResult ae_result;
  if (frame_info.ae_stats_input_mode == AeStatsInputMode::kFromVendorAeStats) {
    std::optional<AeStatsEntry*> entry = GetAeStatsEntry(frame_number);
    if (!entry) {
      LOGF(ERROR) << "Cannot find AE stats entry for frame " << frame_number;
      return ae_parameters;
    }
    AwbInfo awb_info;
    for (int i = 0; i < 4; ++i) {
      awb_info.gains[i] = frame_info.rggb_gains[i];
    }
    for (int i = 0; i < 9; ++i) {
      awb_info.ccm[i] = frame_info.ccm[i];
    }
    const Range<float>& tet_range = (*entry)->tet_range.has_value()
                                        ? (*entry)->tet_range.value()
                                        : device_tet_range;
    if ((*entry)->tet_range.has_value()) {
      DVLOGF(2) << "Using TET range from IPU6 camera HAL: "
                << (*entry)->tet_range.value();
    }
    ae_result = gcam_ae_->ComputeGcamAe(
        frame_info.active_array_dimension.width,
        frame_info.active_array_dimension.height, ae_metadata, awb_info,
        (*entry)->ae_stats, {tet_range.lower(), tet_range.upper()},
        max_hdr_ratio);
    ae_parameters.tet_range = tet_range;
  } else {  // AeStatsInputMode::kFromYuvImage
    if (!frame_info.HasYuvBuffer()) {
      return ae_parameters;
    }
    if (frame_info.acquire_fence.is_valid() &&
        sync_wait(frame_info.acquire_fence.get(), 300) != 0) {
      LOGF(WARNING) << "sync_wait failed";
      return ae_parameters;
    }

    buffer_handle_t buffer_handle = frame_info.yuv_buffer;
    size_t buffer_width = CameraBufferManager::GetWidth(buffer_handle);
    size_t buffer_height = CameraBufferManager::GetHeight(buffer_handle);
    auto* buf_mgr = CameraBufferManager::GetInstance();
    struct android_ycbcr ycbcr;
    buf_mgr->LockYCbCr(buffer_handle, 0, 0, 0, buffer_width, buffer_height,
                       &ycbcr);
    // NV12 is the only support format at the moment.
    YuvBuffer yuv_buffer;
    yuv_buffer.format = YuvFormat::kNv12;
    yuv_buffer.width = buffer_width;
    yuv_buffer.height = buffer_height;
    // Y plane.
    yuv_buffer.planes[0].width = yuv_buffer.width;
    yuv_buffer.planes[0].height = yuv_buffer.height;
    yuv_buffer.planes[0].stride =
        CameraBufferManager::GetPlaneStride(buffer_handle, 0);
    yuv_buffer.planes[0].data = reinterpret_cast<uint8_t*>(ycbcr.y);
    // UV plane.
    yuv_buffer.planes[1].width = yuv_buffer.width / 2;
    yuv_buffer.planes[1].height = yuv_buffer.height / 2;
    yuv_buffer.planes[1].stride =
        CameraBufferManager::GetPlaneStride(buffer_handle, 1);
    yuv_buffer.planes[1].data = reinterpret_cast<uint8_t*>(ycbcr.cb);

    ae_result = gcam_ae_->ComputeLinearizedGcamAe(
        ae_metadata, std::move(yuv_buffer), max_hdr_ratio);

    buf_mgr->Unlock(buffer_handle);
  }

  ae_parameters.short_tet = ae_result.short_tet;
  ae_parameters.long_tet = ae_result.long_tet;
  ae_parameters.log_scene_brightness = ae_result.log_scene_brightness;
  return ae_parameters;
}

std::optional<GcamAeDeviceAdapterIpu6::AeStatsEntry*>
GcamAeDeviceAdapterIpu6::GetAeStatsEntry(int frame_number, bool create_entry) {
  int index = frame_number % ae_stats_.size();
  AeStatsEntry& entry = ae_stats_[index];
  if (entry.frame_number != frame_number) {
    if (!create_entry) {
      return std::nullopt;
    }
    // Clear the outdated AE stats.
    entry.frame_number = frame_number;
    entry.ae_stats = {};
  }
  return &entry;
}

}  // namespace cros
