/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_FACE_DETECTION_FACE_DETECTION_STREAM_MANIPULATOR_H_
#define CAMERA_FEATURES_FACE_DETECTION_FACE_DETECTION_STREAM_MANIPULATOR_H_

#include <memory>
#include <vector>

#include "common/camera_hal3_helpers.h"
#include "common/metadata_logger.h"
#include "common/reloadable_config_file.h"
#include "common/stream_manipulator.h"
#include "cros-camera/camera_face_detection.h"
#include "cros-camera/common_types.h"
#include "cros-camera/cros_camera_hal.h"

namespace cros {

// A wrapper for the FaceSSD-based CrOS face detector.
class FaceDetectionStreamManipulator : public StreamManipulator {
 public:
  // By default the config is loaded from the feature config file path specified
  // in the feature profile. For testing or debugging, the feature config can be
  // overridden by the override config file below. The file should contain a
  // JSON map for the options defined below.
  static constexpr const char kOverrideFaceDetectionConfigFile[] =
      "/run/camera/face_detection_config.json";

  struct Options {
    // Uses CrOS face detector for face detection instead of the vendor one.
    bool enable = false;

    // Controls the duty cycle of CrOS face detector. The face detector will run
    // every |fd_frame_interval| frames.
    int fd_frame_interval = 10;

    // Whether to log per-frame metadata using MetadataLogger.
    bool log_frame_metadata = false;

    // Whether to forcibly add face rectangles to result metadata.
    bool debug = false;
  };

  explicit FaceDetectionStreamManipulator(
      base::FilePath config_file_path,
      base::OnceCallback<void(FaceDetectionResultCallback)>
          set_face_detection_result_callback);

  ~FaceDetectionStreamManipulator() override = default;

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
  struct FrameInfo {
    int frame_number = -1;
    uint8_t face_detect_mode;
  };

  buffer_handle_t SelectFaceDetectionBuffer(Camera3CaptureDescriptor& result);
  void RecordClientRequestSettings(Camera3CaptureDescriptor* request);
  void RestoreClientRequestSettings(Camera3CaptureDescriptor* result);
  void SetFaceDetectionMode(Camera3CaptureDescriptor* request);
  void SetResultAeMetadata(Camera3CaptureDescriptor* result);
  FrameInfo& GetOrCreateFrameInfoEntry(int frame_number);
  void OnOptionsUpdated(const base::Value::Dict& json_values);
  void OnFaceDetected(uint32_t frame_number,
                      FaceDetectResult detect_result,
                      std::vector<human_sensing::CrosFace> faces);
  FaceDetectionResult GetLatestFaces();

  // Face detector settings.
  ReloadableConfigFile config_;
  Options options_;
  Size active_array_dimension_;
  uint8_t active_face_detect_mode_ = ANDROID_STATISTICS_FACE_DETECT_MODE_OFF;

  StreamManipulator::Callbacks callbacks_;

  // Protects |latest_faces_| and |frame_info_| since they can be accessed on
  // different threads.
  base::Lock lock_;

  // The latest face detection result detected by the CrOS face detector.
  FaceDetectionResult latest_face_detection_result_ GUARDED_BY(lock_);

  // Ring buffer for the per-frame face detection metadata.
  static constexpr size_t kFrameInfoRingBufferSize = 12;
  std::array<FrameInfo, kFrameInfoRingBufferSize> frame_info_ GUARDED_BY(lock_);

  // Metadata logger for tests and debugging.
  MetadataLogger metadata_logger_;

  // face_detector_ needs to be destructed first since the OnFaceDetected
  // callback use other members.
  std::unique_ptr<FaceDetector> face_detector_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_FACE_DETECTION_FACE_DETECTION_STREAM_MANIPULATOR_H_
