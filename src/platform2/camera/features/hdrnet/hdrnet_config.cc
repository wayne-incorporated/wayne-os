/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/hdrnet/hdrnet_config.h"

#include "common/reloadable_config_file.h"

namespace cros {

constexpr char kDumpBuffer[] = "dump_buffer";
constexpr char kHdrNetEnable[] = "hdrnet_enable";
constexpr char kHdrRatio[] = "hdr_ratio";
constexpr char kMaxGainBlendThreshold[] = "max_gain_blend_threshold";
constexpr char kSpatialFilterSigma[] = "spatial_filter_sigma";
constexpr char kRangeFilterSigma[] = "range_filter_sigma";
constexpr char kIirFilterStrength[] = "iir_filter_strength";

void ParseHdrnetJsonOptions(const base::Value::Dict& json_values,
                            HdrNetConfig::Options& options) {
  LoadIfExist(json_values, kHdrNetEnable, &options.hdrnet_enable);
  LoadIfExist(json_values, kDumpBuffer, &options.dump_buffer);
  LoadIfExist(json_values, kHdrRatio, &options.hdr_ratio);
  LoadIfExist(json_values, kMaxGainBlendThreshold,
              &options.max_gain_blend_threshold);
  LoadIfExist(json_values, kSpatialFilterSigma, &options.spatial_filter_sigma);
  LoadIfExist(json_values, kRangeFilterSigma, &options.range_filter_sigma);
  LoadIfExist(json_values, kIirFilterStrength, &options.iir_filter_strength);

  CHECK_GE(options.hdr_ratio, 1.0f);
  CHECK_LE(options.max_gain_blend_threshold, 1.0f);
  CHECK_GE(options.max_gain_blend_threshold, 0.0f);
  CHECK_LE(options.iir_filter_strength, 1.0f);
  CHECK_GE(options.iir_filter_strength, 0.0f);
}

}  // namespace cros
