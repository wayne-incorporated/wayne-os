/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_GCAM_AE_GCAM_AE_METRICS_H_
#define CAMERA_FEATURES_GCAM_AE_GCAM_AE_METRICS_H_

#include <cstdint>

namespace cros {

// GcamAeMetrics contains the metrics that we want to track for each camera
// session.
struct GcamAeMetrics {
  // Accumulated convergence latency in number of frames and the total number of
  // samples.
  int accumulated_convergence_latency_frames = 0;
  int num_convergence_samples = 0;

  // Accumulated HDR ratio and the total number of samples. Assuming the scene
  // does not change drastically, average HDR ratio gives us an idea about the
  // dynamic range of the environment during the session.
  double accumulated_hdr_ratio = 0.0f;
  int num_hdr_ratio_samples = 0;

  // Accumulated TET and the total number of samples. Assuming the scene does
  // not change drastically, the average TET gives us an idea about the
  // environment brightness during the session.
  double accumulated_tet = 0.0f;
  int num_tet_samples = 0;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_GCAM_AE_GCAM_AE_METRICS_H_
