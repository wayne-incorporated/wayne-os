/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/gcam_ae/gcam_ae_device_adapter.h"

#if USE_IPU6 || USE_IPU6EP
#include "features/gcam_ae/gcam_ae_device_adapter_ipu6.h"
#endif

namespace cros {

// static
std::unique_ptr<GcamAeDeviceAdapter> GcamAeDeviceAdapter::CreateInstance() {
#if USE_IPU6 || USE_IPU6EP
  return std::make_unique<GcamAeDeviceAdapterIpu6>();
#else
  return std::make_unique<GcamAeDeviceAdapter>();
#endif
}

bool GcamAeDeviceAdapter::WriteRequestParameters(
    Camera3CaptureDescriptor* request) {
  return true;
}

bool SetExposureTargetVendorTag(Camera3CaptureDescriptor* request,
                                float exposure_target) {
  // Returns false by default indicating the exposure target vendor tag is not
  // supported.
  return false;
}

bool GcamAeDeviceAdapter::ExtractAeStats(Camera3CaptureDescriptor* result,
                                         MetadataLogger* metadata_logger) {
  return true;
}

bool GcamAeDeviceAdapter::HasAeStats(int frame_number) {
  return true;
}

AeParameters GcamAeDeviceAdapter::ComputeAeParameters(
    int frame_number,
    const AeFrameInfo& frame_info,
    const Range<float>& device_tet_range,
    float max_hdr_ratio) {
  return AeParameters();
}

}  // namespace cros
