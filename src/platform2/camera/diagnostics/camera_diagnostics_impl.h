// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_DIAGNOSTICS_CAMERA_DIAGNOSTICS_IMPL_H_
#define CAMERA_DIAGNOSTICS_CAMERA_DIAGNOSTICS_IMPL_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "camera/mojo/camera_diagnostics.mojom.h"
#include "common/privacy_shutter_detector_impl.h"

namespace cros {

class CameraDiagnosticsImpl final : public cros::mojom::CameraDiagnostics {
 public:
  CameraDiagnosticsImpl();
  CameraDiagnosticsImpl(CameraDiagnosticsImpl&) = delete;
  CameraDiagnosticsImpl& operator=(const CameraDiagnosticsImpl&) = delete;
  void SetYuvAnalysisEnabled(bool state) final;
  void GetYuvAnalysisEnabled(GetYuvAnalysisEnabledCallback callback) final;
  void AnalyzeYuvFrame(mojom::CameraDiagnosticsFramePtr buffer,
                       AnalyzeYuvFrameCallback callback) final;
  void GetDiagnosticsResult(GetDiagnosticsResultCallback callback) final;

 private:
  uint32_t analysis_result_;
  bool yuv_analysis_enabled_;
  std::unique_ptr<PrivacyShutterDetector> privacy_shutter_detector_;
};

}  // namespace cros

#endif  // CAMERA_DIAGNOSTICS_CAMERA_DIAGNOSTICS_IMPL_H_
