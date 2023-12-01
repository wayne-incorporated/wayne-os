/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_EFFECTS_EFFECTS_STREAM_MANIPULATOR_H_
#define CAMERA_FEATURES_EFFECTS_EFFECTS_STREAM_MANIPULATOR_H_

#include "common/stream_manipulator.h"

#include <memory>

#include <base/files/file_path.h>

namespace cros {

class StillCaptureProcessor;

class EffectsStreamManipulator : public StreamManipulator {
 public:
  static std::unique_ptr<EffectsStreamManipulator> Create(
      base::FilePath config_file_path,
      RuntimeOptions* runtime_options,
      std::unique_ptr<StillCaptureProcessor> still_capture_processor,
      void (*callback)(bool) = nullptr);
};

}  // namespace cros

#endif  // CAMERA_FEATURES_EFFECTS_EFFECTS_STREAM_MANIPULATOR_H_
