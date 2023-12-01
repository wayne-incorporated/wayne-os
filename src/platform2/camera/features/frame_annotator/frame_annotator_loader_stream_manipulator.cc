/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/frame_annotator/frame_annotator_loader_stream_manipulator.h"

#include <utility>

#include <dlfcn.h>

#include <base/files/file_util.h>

#include "features/frame_annotator/libs/utils.h"
#include "features/frame_annotator/tracing.h"

namespace cros {

namespace {

constexpr std::array<const char*, 4> kFrameAnnotatorLibPath = {
    // Check rootfs first for ease of local development.
    "/usr/lib64/libcros_camera_frame_annotator.so",
    "/usr/lib/libcros_camera_frame_annotator.so",

    // By default the .so is installed in the stateful partition on test images.
    "/usr/local/lib64/libcros_camera_frame_annotator.so",
    "/usr/local/lib/libcros_camera_frame_annotator.so",
};

}  // namespace

//
// FrameAnnotatorLoaderStreamManipulator implementations.
//

FrameAnnotatorLoaderStreamManipulator::FrameAnnotatorLoaderStreamManipulator() {
  for (auto* p : kFrameAnnotatorLibPath) {
    if (base::PathExists(base::FilePath(p))) {
      auto native_lib = base::ScopedNativeLibrary(base::FilePath(p));
      if (auto make_frame_annotator_stream_manipulator =
              reinterpret_cast<decltype(&MakeFrameAnnotatorStreamManipulator)>(
                  native_lib.GetFunctionPointer(
                      "MakeFrameAnnotatorStreamManipulator"))) {
        stream_manipulator_ = std::unique_ptr<StreamManipulator>(
            make_frame_annotator_stream_manipulator());
        frame_annotator_lib_ = std::move(native_lib);
        LOGF(INFO) << "FrameAnnotatorLoaderStreamManipulator loaded from " << p;
        break;
      } else {
        LOGF(INFO)
            << "Failed to load FrameAnnotatorLoaderStreamManipulator from " << p
            << " with error: " << native_lib.GetError()->ToString();
      }
    }
  }
}

FrameAnnotatorLoaderStreamManipulator::
    ~FrameAnnotatorLoaderStreamManipulator() {
  stream_manipulator_ = nullptr;
}

bool FrameAnnotatorLoaderStreamManipulator::Initialize(
    const camera_metadata_t* static_info,
    StreamManipulator::Callbacks callbacks) {
  if (stream_manipulator_) {
    return stream_manipulator_->Initialize(static_info, std::move(callbacks));
  }
  callbacks_ = std::move(callbacks);
  return true;
}

bool FrameAnnotatorLoaderStreamManipulator::ConfigureStreams(
    Camera3StreamConfiguration* stream_config,
    const StreamEffectMap* stream_effects_map) {
  if (stream_manipulator_) {
    return stream_manipulator_->ConfigureStreams(stream_config,
                                                 stream_effects_map);
  }
  return true;
}

bool FrameAnnotatorLoaderStreamManipulator::OnConfiguredStreams(
    Camera3StreamConfiguration* stream_config) {
  if (stream_manipulator_) {
    return stream_manipulator_->OnConfiguredStreams(stream_config);
  }
  return true;
}

bool FrameAnnotatorLoaderStreamManipulator::ConstructDefaultRequestSettings(
    android::CameraMetadata* default_request_settings, int type) {
  if (stream_manipulator_) {
    return stream_manipulator_->ConstructDefaultRequestSettings(
        default_request_settings, type);
  }
  return true;
}

bool FrameAnnotatorLoaderStreamManipulator::ProcessCaptureRequest(
    Camera3CaptureDescriptor* request) {
  if (stream_manipulator_) {
    return stream_manipulator_->ProcessCaptureRequest(request);
  }
  return true;
}

bool FrameAnnotatorLoaderStreamManipulator::ProcessCaptureResult(
    Camera3CaptureDescriptor result) {
  if (stream_manipulator_) {
    return stream_manipulator_->ProcessCaptureResult(std::move(result));
  }
  callbacks_.result_callback.Run(std::move(result));
  return true;
}

void FrameAnnotatorLoaderStreamManipulator::Notify(camera3_notify_msg_t msg) {
  TRACE_FRAME_ANNOTATOR();

  if (stream_manipulator_) {
    stream_manipulator_->Notify(std::move(msg));
    return;
  }
  callbacks_.notify_callback.Run(std::move(msg));
}

bool FrameAnnotatorLoaderStreamManipulator::Flush() {
  if (stream_manipulator_) {
    return stream_manipulator_->Flush();
  }
  return true;
}

}  // namespace cros
