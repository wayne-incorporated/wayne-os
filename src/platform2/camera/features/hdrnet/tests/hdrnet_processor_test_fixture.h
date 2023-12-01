/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_HDRNET_TESTS_HDRNET_PROCESSOR_TEST_FIXTURE_H_
#define CAMERA_FEATURES_HDRNET_TESTS_HDRNET_PROCESSOR_TEST_FIXTURE_H_

#include "features/hdrnet/hdrnet_processor_impl.h"

#include <memory>
#include <vector>

#include <base/test/task_environment.h>

#include "common/camera_hal3_helpers.h"
#include "cros-camera/camera_buffer_manager.h"
#include "gpu/gpu_resources.h"
#include "gpu/test_support/gl_test_fixture.h"

namespace cros {

// Test fixture for running tests on the HDRnet processing pipeline.
class HdrNetProcessorTestFixture {
 public:
  HdrNetProcessorTestFixture(const Size& input_size,
                             uint32_t input_hal_pixel_format,
                             const std::vector<Size>& output_sizes,
                             bool use_default_adapter);
  ~HdrNetProcessorTestFixture();

  // Loads input image with the contents in |input_file_path|. By default the
  // input image is populated with a test pattern.
  void LoadInputFile(base::FilePath input_file_path);

  // Loads frame metadata associated with the input image from
  // |metadata_file_path|. By default we generate fake metadata for testing.
  //
  // Loading input image metadata is currently supported on IPU6 platform. The
  // metadata file must contain a JSON map:
  //
  // {
  //   // A list of 2048 floats specifying the 1024 (max_pixel_value, gain)
  //   // pairs, same as what the INTEL_VENDOR_CAMERA_TONE_MAP_CURVE vendor tag
  //   // reports.
  //   "tonemap_curve": [...]
  // }
  void LoadProcessingMetadata(base::FilePath metadata_file_path);

  // Loads the HDRnet processing config from |hdrnet_config_path|.
  void LoadHdrnetConfig(base::FilePath hdrnet_config_path);

  void ProcessResultMetadata(Camera3CaptureDescriptor* result);

  // Runs the HDRnet processing pipeline. Custom input image, metadata and
  // processing config must be loaded using the methods above before calling
  // Run() to have effect.
  base::ScopedFD Run(int frame_number, HdrnetMetrics& metrics);

  // Produces a fake capture result that can be used in the test.
  Camera3CaptureDescriptor ProduceFakeCaptureResult();

  // Dumps the input and output buffers with |file_prefix| prepended to the
  // dumped file name.
  void DumpBuffers(const char* file_prefix);

  HdrNetProcessorImpl* processor() const { return processor_.get(); }
  const SharedImage& input_image() const { return input_image_; }
  std::vector<buffer_handle_t> output_buffers() const {
    std::vector<buffer_handle_t> output_buffers;
    for (const auto& b : output_buffers_) {
      output_buffers.push_back(*b.get());
    }
    return output_buffers;
  }

 protected:
  void InitializeOnGpuThread(const Size& input_size,
                             uint32_t input_hal_pixel_format,
                             const std::vector<Size>& output_sizes,
                             bool use_default_adapter);
  void TearDownOnGpuThread();
  base::ScopedFD RunOnGpuThread(int frame_number, HdrnetMetrics& metrics);
  void DumpBuffersOnGpuThread(const char* file_prefix);

  base::test::SingleThreadTaskEnvironment task_environment_;
  GpuResources gpu_resources_;

  // Access to the |processor_| and the buffers need to sequence on the GPU task
  // runner.
  std::unique_ptr<HdrNetProcessorImpl> processor_;
  ScopedBufferHandle input_buffer_;
  SharedImage input_image_;
  std::vector<ScopedBufferHandle> output_buffers_;

  HdrNetConfig::Options options_ = {
      .hdrnet_enable = true,
  };

  // Fake data for testing.
  uint32_t frame_number_ = 0;
  android::CameraMetadata result_metadata_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_HDRNET_TESTS_HDRNET_PROCESSOR_TEST_FIXTURE_H_
