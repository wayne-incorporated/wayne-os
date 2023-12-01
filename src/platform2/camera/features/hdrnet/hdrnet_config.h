/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_HDRNET_HDRNET_CONFIG_H_
#define CAMERA_FEATURES_HDRNET_HDRNET_CONFIG_H_

#include <base/containers/flat_map.h>
#include <base/files/file_path.h>
#include <base/files/file_path_watcher.h>
#include <base/synchronization/lock.h>
#include <base/values.h>

namespace cros {

// The Config class holds all the settings that controls the operation and
// behaviors of the HDRnet pipeline.
class HdrNetConfig {
 public:
  // By default the config is loaded from the feature config file path specified
  // in the feature profile. For testing or debugging, the feature config can be
  // override by the config override file below. The file should contain a JSON
  // map for the options defined below.
  static constexpr const char kOverrideHdrNetConfigFile[] =
      "/run/camera/hdrnet_config.json";

  struct Options {
    // Enables the HDRnet pipeline to produce output frames.
    bool hdrnet_enable = false;

    // Dumps intermediate processing buffers for debugging.
    bool dump_buffer = false;

    // Whether to log per-frame metadata using MetadataLogger.
    bool log_frame_metadata = false;

    // The HDR ratio use for HDRnet rendering. Only effective if Gcam AE isn't
    // running.
    float hdr_ratio = 1.0f;

    // |max_gain_blend_threshold| is a value in [0.0, 1.0] that defines a
    // threshold for the pixel luma intensity below which the HDR ratio applied
    // to the pixel will be linearly interpolated between [1.0, |hdr_ratio|]. If
    // set to 0, the interpolation is disabled.
    float max_gain_blend_threshold = 0.0f;

    // Spatial and temporal filtering parameters for the HDRnet grid. Setting
    // the parameters to 0 disables the filtering.
    float spatial_filter_sigma = 0.0f;
    float range_filter_sigma = 0.0f;
    float iir_filter_strength = 0.0f;

    // Whether to enable the spatiotemporal denoiser.
    bool denoiser_enable = false;

    // The temporal denoising filter strength of the denoiser in [0.0, 1.0].
    // Value close to 1.0 will result in stronger denoising.
    float iir_temporal_convergence = 0.7f;

    // The number of spatial denoising passes to run. Disabled by default
    // because experiments show that temporal denoising is good enough for
    // HDRnet.
    int num_spatial_passes = 0;

    // The spatial denoising filter strength multiplier. Larger value will
    // result in stronger denoising.
    float spatial_strength = 1.5f;
  };
};

// Helper function to parse general HDRnet options from the give JSON values.
void ParseHdrnetJsonOptions(const base::Value::Dict& json_values,
                            HdrNetConfig::Options& options);

}  // namespace cros

#endif  // CAMERA_FEATURES_HDRNET_HDRNET_CONFIG_H_
