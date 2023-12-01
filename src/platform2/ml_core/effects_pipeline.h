// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_CORE_EFFECTS_PIPELINE_H_
#define ML_CORE_EFFECTS_PIPELINE_H_

#include <brillo/brillo_export.h>

#include <stdint.h>
#include <memory>
#include <string>

#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <GLES2/gl2ext.h>

#include <base/files/file_path.h>
#include <ml_core/effects_pipeline_bindings.h>

namespace cros {

// This is used to receive a callback from the EffectsPipeline when an
// ImageFrame result is available.
class BRILLO_EXPORT ProcessedFrameObserver {
 public:
  virtual ~ProcessedFrameObserver() = default;
  virtual void OnFrameProcessed(int64_t timestamp,
                                GLuint texture,
                                uint32_t frame_width,
                                uint32_t frame_height) = 0;
};

// Wrapper around the Effects Pipeline C bindings that are imported
// from the libcros_ml_core_internal.so.
class BRILLO_EXPORT EffectsPipeline {
 public:
  virtual ~EffectsPipeline() = default;

  // Create an instance of the Pipeline.
  static std::unique_ptr<EffectsPipeline> Create(
      const base::FilePath& dlc_root_path,
      EGLContext share_context,
      const base::FilePath& caching_dir_override = base::FilePath(""));

  // Queue an input frame (ImageFormat::SRGB / RG24 / RGB888) for processing.
  virtual bool ProcessFrame(int64_t timestamp,
                            GLuint frame_texture,
                            uint32_t frame_width,
                            uint32_t frame_height) = 0;

  // Wait until all the queued frames are processed.
  virtual bool Wait() = 0;

  // Sets an observer for receiving the final rendered image. Must be called
  // before ProcessFrame. Takes ownership of the observer.
  virtual bool SetRenderedImageObserver(
      std::unique_ptr<ProcessedFrameObserver> observer) = 0;

  // Select effect to apply. `callback` is called when the effect has been
  // fully set up, which includes loading any TFLite models and preparing
  // them for execution.
  virtual void SetEffect(EffectsConfig* effects_config,
                         void (*callback)(bool)) = 0;
};

}  // namespace cros

#endif  // ML_CORE_EFFECTS_PIPELINE_H_
