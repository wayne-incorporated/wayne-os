/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_HDRNET_HDRNET_PROCESSOR_DEVICE_ADAPTER_H_
#define CAMERA_FEATURES_HDRNET_HDRNET_PROCESSOR_DEVICE_ADAPTER_H_

#include <memory>
#include <vector>

#include <system/camera_metadata.h>

#include <base/task/single_thread_task_runner.h>

#include "common/camera_hal3_helpers.h"
#include "common/metadata_logger.h"
#include "features/hdrnet/hdrnet_config.h"
#include "features/hdrnet/hdrnet_metrics.h"
#include "gpu/gpu_resources.h"
#include "gpu/shared_image.h"

namespace cros {

// Device specilization for the pre-processing and post-processing of the HDRnet
// pipeline.
//
// The default HdrNetProcessorDeviceAdapter implementation does nothing.
class HdrNetProcessorDeviceAdapter {
 public:
  static std::unique_ptr<HdrNetProcessorDeviceAdapter> CreateInstance(
      const camera_metadata_t* static_info,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  virtual ~HdrNetProcessorDeviceAdapter() = default;
  virtual bool Initialize(GpuResources* gpu_resources,
                          Size input_size,
                          const std::vector<Size>& output_sizes);
  virtual void TearDown();

  // Called on every frame to allow the adapter to set device specific
  // control metadata (e.g. vendor tags) for each capture request.
  virtual bool WriteRequestParameters(Camera3CaptureDescriptor* request,
                                      MetadataLogger* metadata_logger);

  // Called on every frame with the per-frame capture result metadata.
  virtual void ProcessResultMetadata(Camera3CaptureDescriptor* result,
                                     MetadataLogger* metadata_logger);

  // Runs the device-specific HDRnet processing pipeline.
  virtual bool Run(int frame_number,
                   const HdrNetConfig::Options& options,
                   const SharedImage& input,
                   const SharedImage& output,
                   HdrnetMetrics* hdrnet_metrics);
};

}  // namespace cros

#endif  // CAMERA_FEATURES_HDRNET_HDRNET_PROCESSOR_DEVICE_ADAPTER_H_
