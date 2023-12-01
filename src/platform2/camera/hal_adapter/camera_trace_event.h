/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_ADAPTER_CAMERA_TRACE_EVENT_H_
#define CAMERA_HAL_ADAPTER_CAMERA_TRACE_EVENT_H_

#include <string>

#include <base/strings/stringprintf.h>

#include "cros-camera/tracing.h"

namespace cros {

enum class HalAdapterTraceEvent {
  kCapture,
};

#define TRACE_HAL_ADAPTER(...) \
  TRACE_EVENT_AUTOGEN(kCameraTraceCategoryHalAdapter, ##__VA_ARGS__);

#define TRACE_HAL_ADAPTER_EVENT(event, ...) \
  TRACE_EVENT(kCameraTraceCategoryHalAdapter, event, ##__VA_ARGS__);

#define TRACE_HAL_ADAPTER_BEGIN(event, track, ...)                \
  TRACE_EVENT_BEGIN(kCameraTraceCategoryHalAdapter, event, track, \
                    ##__VA_ARGS__);

#define TRACE_HAL_ADAPTER_END(track) \
  TRACE_EVENT_END(kCameraTraceCategoryHalAdapter, track);

// Generates unique track by given |event|, |primary_id| and |secondary_id|. For
// |secondary_id|, only the last 16 bits will be used.
perfetto::Track GetTraceTrack(HalAdapterTraceEvent event,
                              int primary_id = 0,
                              int secondary_id = 0);

perfetto::StaticString ToString(HalAdapterTraceEvent event);

}  // namespace cros

#endif  // CAMERA_HAL_ADAPTER_CAMERA_TRACE_EVENT_H_
