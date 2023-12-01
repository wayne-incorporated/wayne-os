/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_ZSL_ZSL_STREAM_MANIPULATOR_H_
#define CAMERA_FEATURES_ZSL_ZSL_STREAM_MANIPULATOR_H_

#include "common/stream_manipulator.h"

#include <atomic>
#include <memory>
#include <vector>

#include <hardware/camera3.h>

#include "features/zsl/zsl_helper.h"

namespace cros {

class ZslStreamManipulator : public StreamManipulator {
 public:
  ZslStreamManipulator();

  ~ZslStreamManipulator() override;

  static bool UpdateVendorTags(VendorTagManager& vendor_tag_manager);
  static bool UpdateStaticMetadata(android::CameraMetadata* static_info);

  // Implementations of StreamManipulator.
  bool Initialize(const camera_metadata_t* static_info,
                  StreamManipulator::Callbacks callbacks) override;
  bool ConfigureStreams(Camera3StreamConfiguration* stream_config,
                        const StreamEffectMap* stream_effects_map) override;
  bool OnConfiguredStreams(Camera3StreamConfiguration* stream_config) override;
  bool ConstructDefaultRequestSettings(
      android::CameraMetadata* default_request_settings, int type) override;
  bool ProcessCaptureRequest(Camera3CaptureDescriptor* request) override;
  bool ProcessCaptureResult(Camera3CaptureDescriptor result) override;
  void Notify(camera3_notify_msg_t msg) override;
  bool Flush() override;

 private:
  bool can_attempt_zsl_ = false;

  int partial_result_count_ = 0;

  StreamManipulator::Callbacks callbacks_;

  // A helper class that includes various functions for the mechanisms of ZSL.
  std::unique_ptr<ZslHelper> zsl_helper_;

  bool zsl_stream_attached_ = false;

  // Whether ZSL is enabled. The value can change after each ConfigureStreams().
  std::atomic<bool> zsl_enabled_ = false;

  // The stream configured for ZSL requests.
  camera3_stream_t* zsl_stream_ = nullptr;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_ZSL_ZSL_STREAM_MANIPULATOR_H_
