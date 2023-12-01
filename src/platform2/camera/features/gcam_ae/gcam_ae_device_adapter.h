/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_GCAM_AE_GCAM_AE_DEVICE_ADAPTER_H_
#define CAMERA_FEATURES_GCAM_AE_GCAM_AE_DEVICE_ADAPTER_H_

#include <memory>

#include <camera/camera_metadata.h>

#include "common/camera_hal3_helpers.h"
#include "common/metadata_logger.h"
#include "features/gcam_ae/ae_info.h"

namespace cros {

// AeDeviceAdapter handles the device or platform specific AE stats extraction
// and translation, and the AE algorithm implementation (e.g. calls down to the
// device-specific Gcam AE implementation).
class GcamAeDeviceAdapter {
 public:
  static std::unique_ptr<GcamAeDeviceAdapter> CreateInstance();

  virtual ~GcamAeDeviceAdapter() = default;

  // Called by GcamAeController to allow the adapter to set device specific
  // control metadata (e.g. vendor tags) for each capture request.
  virtual bool WriteRequestParameters(Camera3CaptureDescriptor* request) = 0;

  // Called by GcamAeController to set the exposure target through vendor tag.
  // Returns true if the camera HAL accepts the exposure target vendor tag and
  // |tet| is successfully configured. Returns false if the camera HAL does not
  // support setting exposure target through vendor tag, or the tag is not
  // successfully configured.
  //
  // |exposure_target| has the same format as the TET computed by Gcam AE:
  //   exposure_time (ms) * analog_gain * digital_gain
  virtual bool SetExposureTargetVendorTag(Camera3CaptureDescriptor* request,
                                          float exposure_target) = 0;

  // Called by GcamAeController to extract the device specific AE stats from
  // |result|.
  virtual bool ExtractAeStats(Camera3CaptureDescriptor* result,
                              MetadataLogger* metadata_logger = nullptr) = 0;

  // Whether there's AE stats available for frame |frame_number|.
  virtual bool HasAeStats(int frame_number) = 0;

  // Compute the AE parameters from |frame_info| and the AE stats previously
  // extracted for frame |frame_number|.  |device_tet_range| and |max_hdr_ratio|
  // are passed as input parameter to Gcam AE.
  virtual AeParameters ComputeAeParameters(int frame_number,
                                           const AeFrameInfo& frame_info,
                                           const Range<float>& device_tet_range,
                                           float max_hdr_ratio) = 0;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_GCAM_AE_GCAM_AE_DEVICE_ADAPTER_H_
