/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_FRAME_ANNOTATOR_H_
#define CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_FRAME_ANNOTATOR_H_

#include <optional>

#include <base/functional/callback_forward.h>
#include <hardware/camera3.h>
#include <skia/core/SkCanvas.h>

#include "common/camera_hal3_helpers.h"

namespace cros {

// Interface class that can be used to plot information on frame. The interface
// is a subset of standard camera HAL3, so different usages can collect its own
// information through the API.
class FrameAnnotator {
 public:
  // The default frame annotator config file. The file should contain a JSON map
  // for the Options defined below.
  static constexpr const char kFrameAnnotatorConfigFile[] =
      "/etc/camera/frame_annotator_config.json";
  // The frame annotator config file that overrides the default one. The file
  // should contain a JSON map for the Options defined below.
  static constexpr const char kOverrideFrameAnnotatorConfigFile[] =
      "/run/camera/frame_annotator_config.json";

  enum class FlipType {
    // kHorizontal for front-facing camera, kNone for back-facing camera.
    kDefault,
    kNone,
    kHorizontal,
    kVertical,
    kRotate180,
  };

  struct Options {
    // Option for selecting the flip type of current camera. Can be overridden
    // by the override config file.
    FlipType flip_type = FlipType::kDefault;

    // Options for selecting which frame annotators to be enabled. This will not
    // be overridden when the override config file change.
    bool face_rectangles_frame_annotator = false;
    bool metadata_previewer_frame_annotator = false;

    // Options for selecting which face features to be displayed. These are used
    // by FaceRectanglesFreameAnnotator. Can be overridden by the override
    // config file.
    bool face_rectangles = true;
    bool face_rectangles_confidence = true;
    bool face_landmarks = true;
    bool face_landmarks_confidence = true;
  };

  virtual ~FrameAnnotator() = default;

  // A hook to the camera3_device_ops::initialize(). Will be called by
  // FrameAnnotatorStreamManipulator with the camera device static metadata
  // |static_info|.
  virtual bool Initialize(const camera_metadata_t* static_info) = 0;

  // A hook to the camera3_callback_ops::process_capture_result(). Will be
  // called by FrameAnnotatorStreamManipulator for each capture result |result|
  // produced by the camera HAL implementation. This function should only be
  // used for collecting information. Any implementations of this function
  // should not modify the result.
  virtual bool ProcessCaptureResult(const Camera3CaptureDescriptor* result) = 0;

  // Returns true if the frame annotator wants to plot the frame. This function
  // would suggest the FrameAnnotatorStreamManipulator do further optimizations
  // if no plot needed.
  virtual bool IsPlotNeeded() const = 0;

  // A function to plot the frame with Skia's canvas API. Will be called once by
  // FrameAnnotatorStreamManipulator for ecahc yuv frame.
  virtual bool Plot(SkCanvas* canvas) = 0;

  // A callback function for updating frame annotator options. Will be called
  // when any kFrameAnnotatorOverrideOptionsFile content update occurred.
  virtual void UpdateOptions(const Options& options) = 0;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_FRAME_ANNOTATOR_H_
