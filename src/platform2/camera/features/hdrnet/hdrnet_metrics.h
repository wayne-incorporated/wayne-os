/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_HDRNET_HDRNET_METRICS_H_
#define CAMERA_FEATURES_HDRNET_HDRNET_METRICS_H_

#include <base/containers/flat_map.h>

#include <cros-camera/camera_metrics.h>

namespace cros {

// HdrnetMetrics contains the metrics that we want to track for each camera
// session that enables HDRnet.
struct HdrnetMetrics {
  // The type of streams configured.
  HdrnetStreamConfiguration stream_config =
      HdrnetStreamConfiguration::kSingleYuvStream;

  // The number of HDRnet streams that are configured concurrently.
  int num_concurrent_hdrnet_streams = 0;

  // The maximum size of the HDRnet streams configured for YUV output.
  int max_yuv_stream_size = 0;

  // The maximum size of the HDRnet streams configured for BLOB output.
  int max_blob_stream_size = 0;

  // The maximum number of buffers rendered with one HDRnet stream.
  int max_output_buffers_rendered = 0;

  // The number of occurrence for each error that can compromise the HDRnet
  // feature, either causing frame drops or stops the pipeline from running
  // completely.
  base::flat_map<HdrnetError, int> errors = {};

  // The number of HDRnet-rendered still shots taken.
  int num_still_shot_taken = 0;

  // The accumulated latency in us of the different HDRnet processing stages.
  int64_t accumulated_preprocessing_latency_us = 0;
  int64_t accumulated_rgb_pipeline_latency_us = 0;
  int64_t accumulated_postprocessing_latency_us = 0;

  // The total number of frames processed by the HDRnet pipeline.
  int num_frames_processed = 0;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_HDRNET_HDRNET_METRICS_H_
