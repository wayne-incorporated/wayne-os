/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "cros-camera/tracing.h"

PERFETTO_TRACK_EVENT_STATIC_STORAGE();

namespace cros {

void InitializeCameraTrace() {
  perfetto::TracingInitArgs args;
  args.backends |= perfetto::kSystemBackend;
  perfetto::Tracing::Initialize(args);
  cros_camera::TrackEvent::Register();
}

}  // namespace cros
