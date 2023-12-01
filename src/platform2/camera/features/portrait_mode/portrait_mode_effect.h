/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_PORTRAIT_MODE_PORTRAIT_MODE_EFFECT_H_
#define CAMERA_FEATURES_PORTRAIT_MODE_PORTRAIT_MODE_EFFECT_H_

#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/process/process.h>
#include <base/synchronization/condition_variable.h>
#include <base/synchronization/lock.h>
#include <camera/camera_metadata.h>

#include "common/vendor_tag_manager.h"
#include "cros-camera/camera_buffer_manager.h"
#include "features/portrait_mode/gpu_algo_manager.h"

namespace cros {

// Vendor tag to indicate whether CrOS portrait mode can be attempted.
constexpr char kPortraitModeVendorTagSectionName[] = "com.google";

// 1: enable portrait processing
// 0: disable portrait processing
constexpr char kPortraitModeVendorTagName[] = "com.google.effect.portraitMode";
// The status of SegmentationResult.
constexpr char kPortraitModeResultVendorTagName[] =
    "com.google.effect.portraitModeSegmentationResult";

constexpr uint32_t kPortraitModeVendorKey = kPortraitModeVendorTagStart;
constexpr uint32_t kPortraitModeSegmentationResultVendorKey =
    kPortraitModeVendorTagStart + 1;

enum class SegmentationResult : uint8_t {
  kSuccess = 0,  // Portrait mode segmentation succeeds.
  kFailure = 1,  // Portrait mode segmentation fails.
  kTimeout = 2,  // Portrait processing timeout.
  kNoFaces = 3,  // Portrait mode segmentation fails with no face detected.
  kUnknown = 4
};

class PortraitModeEffect : public base::SupportsWeakPtr<PortraitModeEffect> {
 public:
  PortraitModeEffect();
  PortraitModeEffect(const PortraitModeEffect&) = delete;
  PortraitModeEffect& operator=(const PortraitModeEffect&) = delete;

  // Initializes the portrait mode effect.
  // Args:
  //    |token|: the mojo manager token
  // Returns:
  //    0 on success; corresponding error code on failure.
  int32_t Initialize(CameraMojoChannelManagerToken* token);

  // Applies the portrait mode effect. Currently it is assumed that the effect
  // have the same output resolution and format as that of input.
  // Args:
  //    |can_process_portrait|: can process portrait mode effect
  //    |input_buffer|: input buffer
  //    |orientation|: clockwise rotation angle in degrees to be viewed upright
  //    |segmentation_result|: portrait mode segmentation result
  //    |output_buffer|: output buffer
  // Returns:
  //    0 on success; corresponding error code on failure.
  int32_t ReprocessRequest(bool can_process_portrait,
                           buffer_handle_t input_buffer,
                           uint32_t orientation,
                           SegmentationResult* segmentation_result,
                           buffer_handle_t output_buffer);

 private:
  void UpdateSegmentationResult(SegmentationResult* segmentation_result,
                                const int* result);

  int ConvertYUVToRGB(const ScopedMapping& mapping,
                      void* rgb_buf_addr,
                      uint32_t rgb_buf_stride);

  int ConvertRGBToYUV(void* rgb_buf_addr,
                      uint32_t rgb_buf_stride,
                      const ScopedMapping& mapping);

  void ReturnCallback(uint32_t status, int32_t buffer_handle);

  CameraBufferManager* buffer_manager_;

  GPUAlgoManager* gpu_algo_manager_;

  base::Lock lock_;

  base::ConditionVariable condvar_;

  int32_t return_status_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_PORTRAIT_MODE_PORTRAIT_MODE_EFFECT_H_
