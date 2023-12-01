// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fake/fake_probe_service.h"

#include <base/logging.h>
#include <base/notreached.h>

namespace diagnostics {

FakeProbeService::FakeProbeService() = default;
FakeProbeService::~FakeProbeService() = default;

void FakeProbeService::ProbeProcessInfo(uint32_t process_id,
                                        ProbeProcessInfoCallback callback) {
  NOTIMPLEMENTED();
}

void FakeProbeService::ProbeTelemetryInfo(
    const std::vector<ProbeCategoryEnum>& categories,
    ProbeTelemetryInfoCallback callback) {
  NOTIMPLEMENTED();
}

void FakeProbeService::ProbeMultipleProcessInfo(
    const std::optional<std::vector<uint32_t>>& process_ids,
    bool ignore_single_process_info,
    ProbeMultipleProcessInfoCallback callback) {
  NOTIMPLEMENTED();
}

}  // namespace diagnostics
