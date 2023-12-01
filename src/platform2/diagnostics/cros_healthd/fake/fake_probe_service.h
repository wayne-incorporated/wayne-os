// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_PROBE_SERVICE_H_
#define DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_PROBE_SERVICE_H_

#include <cstdint>
#include <vector>

#include "diagnostics/mojom/public/cros_healthd.mojom.h"

namespace diagnostics {

// Fake implementation of the CrosHealthdProbeService interface.
class FakeProbeService final
    : public ash::cros_healthd::mojom::CrosHealthdProbeService {
 public:
  using ProbeCategoryEnum = ::ash::cros_healthd::mojom::ProbeCategoryEnum;

  FakeProbeService();
  FakeProbeService(const FakeProbeService&) = delete;
  FakeProbeService& operator=(const FakeProbeService&) = delete;
  ~FakeProbeService() override;

  // ash::cros_healthd::mojom::CrosHealthdProbeService overrides:
  void ProbeProcessInfo(uint32_t process_id,
                        ProbeProcessInfoCallback callback) override;
  void ProbeTelemetryInfo(const std::vector<ProbeCategoryEnum>& categories,
                          ProbeTelemetryInfoCallback callback) override;
  void ProbeMultipleProcessInfo(
      const std::optional<std::vector<uint32_t>>& process_ids,
      bool ignore_single_process_info,
      ProbeMultipleProcessInfoCallback callback) override;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_PROBE_SERVICE_H_
