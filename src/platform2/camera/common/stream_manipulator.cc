/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/stream_manipulator.h"

#include <iomanip>
#include <utility>

#include <base/files/file_util.h>

#include "common/still_capture_processor_impl.h"
#include "common/sw_privacy_switch_stream_manipulator.h"
#include "cros-camera/camera_mojo_channel_manager.h"
#include "cros-camera/jpeg_compressor.h"
#include "features/feature_profile.h"
#include "features/rotate_and_crop/rotate_and_crop_stream_manipulator.h"
#include "features/zsl/zsl_stream_manipulator.h"
#include "gpu/gpu_resources.h"

#if USE_CAMERA_FEATURE_HDRNET
#include "features/gcam_ae/gcam_ae_stream_manipulator.h"
#include "features/hdrnet/hdrnet_stream_manipulator.h"
#endif

#if USE_CAMERA_FEATURE_AUTO_FRAMING
#include "features/auto_framing/auto_framing_stream_manipulator.h"
#endif

#if USE_CAMERA_FEATURE_EFFECTS
#include "features/effects/effects_stream_manipulator.h"
#endif

#if USE_CAMERA_FEATURE_FACE_DETECTION || USE_CAMERA_FEATURE_AUTO_FRAMING
#include "features/face_detection/face_detection_stream_manipulator.h"
#endif

#if USE_CAMERA_FEATURE_FRAME_ANNOTATOR
#include "features/frame_annotator/frame_annotator_loader_stream_manipulator.h"
#endif

#if USE_CAMERA_FEATURE_PORTRAIT_MODE
#include "features/portrait_mode/portrait_mode_stream_manipulator.h"
#endif

namespace cros {

void StreamManipulator::RuntimeOptions::SetAutoFramingState(
    mojom::CameraAutoFramingState state) {
  base::AutoLock lock(lock_);
  auto_framing_state_ = state;
}

void StreamManipulator::RuntimeOptions::SetSWPrivacySwitchState(
    mojom::CameraPrivacySwitchState state) {
  {
    base::AutoLock lock(lock_);
    LOGF(INFO) << "SW privacy switch state changed from "
               << sw_privacy_switch_state_ << " to " << state;
    sw_privacy_switch_state_ = state;
  }
}

void StreamManipulator::RuntimeOptions::SetEffectsConfig(
    mojom::EffectsConfigPtr config) {
  base::AutoLock lock(lock_);
  effects_config_ = std::move(config);
}

mojom::EffectsConfigPtr StreamManipulator::RuntimeOptions::GetEffectsConfig() {
  base::AutoLock lock(lock_);
  // Return a copy.
  return effects_config_->Clone();
}

base::FilePath StreamManipulator::RuntimeOptions::GetDlcRootPath() {
  base::AutoLock lock(lock_);
  return dlc_root_path;
}

void StreamManipulator::RuntimeOptions::SetDlcRootPath(
    const base::FilePath& path) {
  base::AutoLock lock(lock_);
  dlc_root_path = path;
}

mojom::CameraAutoFramingState
StreamManipulator::RuntimeOptions::auto_framing_state() {
  base::AutoLock lock(lock_);
  return auto_framing_state_;
}

mojom::CameraPrivacySwitchState
StreamManipulator::RuntimeOptions::sw_privacy_switch_state() {
  base::AutoLock lock(lock_);
  return sw_privacy_switch_state_;
}

// static
bool StreamManipulator::UpdateVendorTags(VendorTagManager& vendor_tag_manager) {
  if (!ZslStreamManipulator::UpdateVendorTags(vendor_tag_manager) ||
      !RotateAndCropStreamManipulator::UpdateVendorTags(vendor_tag_manager)) {
    return false;
  }
#if USE_CAMERA_FEATURE_PORTRAIT_MODE
  if (!PortraitModeStreamManipulator::UpdateVendorTags(vendor_tag_manager)) {
    return false;
  }
#endif
  return true;
}

// static
bool StreamManipulator::UpdateStaticMetadata(
    android::CameraMetadata* static_info) {
  if (!ZslStreamManipulator::UpdateStaticMetadata(static_info) ||
      !RotateAndCropStreamManipulator::UpdateStaticMetadata(static_info)) {
    return false;
  }
#if USE_CAMERA_FEATURE_PORTRAIT_MODE
  if (!PortraitModeStreamManipulator::UpdateStaticMetadata(static_info)) {
    return false;
  }
#endif
  return true;
}

scoped_refptr<base::SingleThreadTaskRunner> StreamManipulator::GetTaskRunner() {
  return nullptr;
}

// static
base::ScopedClosureRunner
StreamManipulator::MakeScopedCaptureResultCallbackRunner(
    CaptureResultCallback& result_callback, Camera3CaptureDescriptor& result) {
  return base::ScopedClosureRunner(base::BindOnce(
      [](StreamManipulator::CaptureResultCallback& cb,
         Camera3CaptureDescriptor& result) { cb.Run(std::move(result)); },
      std::ref(result_callback), std::ref(result)));
}

}  // namespace cros
