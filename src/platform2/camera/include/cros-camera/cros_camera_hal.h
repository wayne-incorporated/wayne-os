/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CROS_CAMERA_HAL_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CROS_CAMERA_HAL_H_

#define CROS_CAMERA_HAL_INFO_SYM CCHI
#define CROS_CAMERA_HAL_INFO_SYM_AS_STR "CCHI"

#include <vector>

#include <base/functional/callback.h>
#include <hardware/camera3.h>
#include <hardware/camera_common.h>

#include "cros-camera/camera_mojo_channel_manager_token.h"

#if USE_CAMERA_FEATURE_FACE_DETECTION || defined(FACE_DETECTION)
#include "cros-camera/camera_face_detection.h"
#endif

namespace cros {

enum class PrivacySwitchState {
  kUnknown,
  kOn,
  kOff,
};

// Synced with CameraClientType in cros_camera_service.mojom.
enum class ClientType {
  kUnknown = 0,
  kTesting = 1,
  kChrome = 2,
  kAndroid = 3,
  kPluginVm = 4,
  kAshChrome = 5,
  kLacrosChrome = 6
};

struct FaceDetectionResult {
  // The frame number that the face detection was run on.
  uint32_t frame_number;

#if USE_CAMERA_FEATURE_FACE_DETECTION || defined(FACE_DETECTION)
  // The detected face ROIs.
  std::vector<human_sensing::CrosFace> faces;
#endif
};

using FaceDetectionResultCallback =
    base::RepeatingCallback<FaceDetectionResult()>;

using PrivacySwitchStateChangeCallback =
    base::RepeatingCallback<void(int camera_id, PrivacySwitchState state)>;

typedef struct cros_camera_hal {
  /**
   * Sets up the camera HAL. The |token| can be used for communication through
   * Mojo.
   */
  void (*set_up)(CameraMojoChannelManagerToken* token) = nullptr;

  /**
   * Tears down the camera HAL.
   */
  void (*tear_down)() = nullptr;

  /**
   * Registers camera privacy switch observer.
   */
  void (*set_privacy_switch_callback)(
      PrivacySwitchStateChangeCallback callback) = nullptr;

  /**
   *  Open the camera device by client type.
   */
  int (*camera_device_open_ext)(const hw_module_t* module,
                                const char* name,
                                hw_device_t** device,
                                ClientType client_type) = nullptr;

  /**
   * Gets the camera info by client type.
   */
  int (*get_camera_info_ext)(int id,
                             struct camera_info* info,
                             ClientType client_type) = nullptr;

  /**
   * Registers facessd detect callback.
   */
  void (*set_face_detection_result_callback)(
      int camera_id, FaceDetectionResultCallback callback) = nullptr;

  /**
   * Sets the software privacy switch state.
   */
  void (*set_privacy_switch_state)(bool on) = nullptr;

  /* reserved for future use */
  void* reserved[4];
} cros_camera_hal_t;

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_CROS_CAMERA_HAL_H_
