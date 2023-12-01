// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/tracing.h"

PERFETTO_TRACK_EVENT_STATIC_STORAGE_IN_NAMESPACE(power_manager);

namespace power_manager {

void InitTracing() {
  perfetto::TracingInitArgs args;
  args.backends |= perfetto::kSystemBackend;
  perfetto::Tracing::Initialize(args);
  power_manager::TrackEvent::Register();
}

}  // namespace power_manager
