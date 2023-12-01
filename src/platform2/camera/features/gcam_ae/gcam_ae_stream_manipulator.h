/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_GCAM_AE_GCAM_AE_STREAM_MANIPULATOR_H_
#define CAMERA_FEATURES_GCAM_AE_GCAM_AE_STREAM_MANIPULATOR_H_

#include "common/stream_manipulator.h"

#include <memory>

#include <base/functional/callback_helpers.h>
#include <base/synchronization/lock.h>
#include <camera/camera_metadata.h>

#include "common/reloadable_config_file.h"
#include "features/gcam_ae/gcam_ae_controller.h"

namespace cros {

class GcamAeStreamManipulator : public StreamManipulator {
 public:
  // By default the config is loaded from the feature config file path specified
  // in the feature profile. For testing or debugging, the feature config can be
  // overridden by the override config file below. The file should contain a
  // JSON map for the options defined below.
  static constexpr const char kOverrideGcamAeConfigFile[] =
      "/run/camera/gcam_ae_config.json";

  struct Options {
    // Whether to log per-frame metadata using MetadataLogger.
    bool log_frame_metadata = false;
  };

  explicit GcamAeStreamManipulator(
      base::FilePath config_file_path,
      GcamAeController::Factory gcam_ae_controller_factory =
          base::NullCallback());

  ~GcamAeStreamManipulator() override = default;

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
  void OnOptionsUpdated(const base::Value::Dict& json_values);

  ReloadableConfigFile config_;
  Options options_;
  android::CameraMetadata static_info_;
  StreamManipulator::Callbacks callbacks_;

  GcamAeController::Factory gcam_ae_controller_factory_;
  // Access to |ae_controller_| is serialized by |ae_controller_lock_| since the
  // capture requests and results come from different threads.
  base::Lock ae_controller_lock_;
  std::unique_ptr<GcamAeController> ae_controller_
      GUARDED_BY(ae_controller_lock_);

  const camera3_stream_t* yuv_stream_ = nullptr;

  // Metadata logger for tests and debugging.
  MetadataLogger metadata_logger_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_GCAM_AE_GCAM_AE_STREAM_MANIPULATOR_H_
