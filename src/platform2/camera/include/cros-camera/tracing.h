/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Perfetto tracing support for cros-camera. See doc/tracing.md for
// documentation about tracing in the camera service.

#ifndef CAMERA_INCLUDE_CROS_CAMERA_TRACING_H_
#define CAMERA_INCLUDE_CROS_CAMERA_TRACING_H_

#include <string>

#include "cros-camera/export.h"

// To export the Perfetto symbols (e.g. kCategoryRegistry).
#define PERFETTO_COMPONENT_EXPORT CROS_CAMERA_EXPORT
#define PERFETTO_EXPORT_COMPONENT CROS_CAMERA_EXPORT

#define PERFETTO_TRACK_EVENT_NAMESPACE cros_camera

#include <perfetto/perfetto.h>

namespace cros {

// One time initialization to connect to Perfetto system backend and register
// the camera trace categories.
void CROS_CAMERA_EXPORT InitializeCameraTrace();

// The camera trace categories.
constexpr char kCameraTraceCategoryAutoFraming[] = "camera.auto_framing";
constexpr char kCameraTraceCategoryCommon[] = "camera.common";
constexpr char kCameraTraceCategoryEffects[] = "camera.effects";
constexpr char kCameraTraceCategoryFaceDetection[] = "camera.face_detection";
constexpr char kCameraTraceCategoryFrameAnnotator[] = "camera.frame_annotator";
constexpr char kCameraTraceCategoryGcamAe[] = "camera.gcam_ae";
constexpr char kCameraTraceCategoryGpuDebug[] = "camera.gpu.debug";
constexpr char kCameraTraceCategoryGpu[] = "camera.gpu";
constexpr char kCameraTraceCategoryHalAdapter[] = "camera.hal_adapter";
constexpr char kCameraTraceCategoryHdrnetDebug[] = "camera.hdrnet.debug";
constexpr char kCameraTraceCategoryHdrnet[] = "camera.hdrnet";
constexpr char kCameraTraceCategoryJpegDebug[] = "camera.jpeg.debug";
constexpr char kCameraTraceCategoryJpeg[] = "camera.jpeg";
constexpr char kCameraTraceCategoryPortraitMode[] = "camera.portrait_mode";
constexpr char kCameraTraceCategoryUsbHal[] = "camera.usb_hal";
constexpr char kCameraTraceCategoryZsl[] = "camera.zsl";

}  // namespace cros

constexpr std::string_view TraceCameraEventName(const char* pretty_function) {
  std::string_view sv(pretty_function);
  size_t paren = sv.rfind('(');
  size_t space = sv.rfind(' ', paren) + 1;
  auto name = sv.substr(space, paren - space);
  if (name.rfind("cros::", 0) == 0) {
    name = name.substr(6);
  }
  return name;
}

#define TRACE_CAMERA_EVENT_NAME TraceCameraEventName(__PRETTY_FUNCTION__)

#define TRACE_EVENT_AUTOGEN(category, ...)                                \
  static const std::string event_##__LINE__(TRACE_CAMERA_EVENT_NAME);     \
  TRACE_EVENT(category, perfetto::StaticString(event_##__LINE__.c_str()), \
              ##__VA_ARGS__)

PERFETTO_DEFINE_CATEGORIES(
    perfetto::Category(cros::kCameraTraceCategoryAutoFraming)
        .SetDescription("Events from CrOS Auto Framing pipeline"),
    perfetto::Category(cros::kCameraTraceCategoryCommon)
        .SetDescription("Events from common CrOS Camera library"),
    perfetto::Category(cros::kCameraTraceCategoryEffects)
        .SetDescription("Events from CrOS Effects pipeline"),
    perfetto::Category(cros::kCameraTraceCategoryFaceDetection)
        .SetDescription("Events from CrOS Face Detection"),
    perfetto::Category(cros::kCameraTraceCategoryFrameAnnotator)
        .SetDescription("Events from CrOS Camera frame annotator"),
    perfetto::Category(cros::kCameraTraceCategoryGcamAe)
        .SetDescription("Events from CrOS Gcam AE pipeline"),
    perfetto::Category(cros::kCameraTraceCategoryGpuDebug)
        .SetDescription("Events from CrOS Camera GPU operations (debug)")
        .SetTags("debug"),
    perfetto::Category(cros::kCameraTraceCategoryGpu)
        .SetDescription("Events from CrOS Camera GPU operations"),
    perfetto::Category(cros::kCameraTraceCategoryHalAdapter)
        .SetDescription("Events from CrOS Camera HAL adapter"),
    perfetto::Category(cros::kCameraTraceCategoryHdrnetDebug)
        .SetDescription("Events from CrOS HDRnet pipeline (debug)")
        .SetTags("debug"),
    perfetto::Category(cros::kCameraTraceCategoryHdrnet)
        .SetDescription("Events from CrOS HDRnet pipeline"),
    perfetto::Category(cros::kCameraTraceCategoryJpegDebug)
        .SetDescription("Events from CrOS JPEG codec (debug)")
        .SetTags("debug"),
    perfetto::Category(cros::kCameraTraceCategoryJpeg)
        .SetDescription("Events from CrOS JPEG codec"),
    perfetto::Category(cros::kCameraTraceCategoryPortraitMode)
        .SetDescription("Events from CrOS Portrait Mode"),
    perfetto::Category(cros::kCameraTraceCategoryUsbHal)
        .SetDescription("Events from CrOS Camera USB HAL"),
    perfetto::Category(cros::kCameraTraceCategoryZsl)
        .SetDescription("Events from CrOS ZSL pipeline"));

#endif  // CAMERA_INCLUDE_CROS_CAMERA_TRACING_H_
