// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/fake_probe_service.h"

#include <utility>

#include <base/check.h>
#include <base/logging.h>

#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace wilco {

namespace {

using ProbeTelemetryInfoCallback =
    base::OnceCallback<void(ash::cros_healthd::mojom::TelemetryInfoPtr)>;

void MissingProbeTelemetryInfoCallback(
    std::vector<ash::cros_healthd::mojom::ProbeCategoryEnum>,
    ProbeTelemetryInfoCallback) {
  DCHECK(nullptr);
}

}  // namespace

FakeProbeService::FakeProbeService()
    : telemetry_callback_(base::BindOnce(MissingProbeTelemetryInfoCallback)) {}

FakeProbeService::~FakeProbeService() = default;

void FakeProbeService::SetProbeTelemetryInfoCallback(
    base::OnceCallback<
        void(std::vector<ash::cros_healthd::mojom::ProbeCategoryEnum>,
             ProbeTelemetryInfoCallback)> callback) {
  telemetry_callback_ = std::move(callback);
}

void FakeProbeService::ProbeTelemetryInfo(
    std::vector<ash::cros_healthd::mojom::ProbeCategoryEnum> categories,
    ProbeTelemetryInfoCallback callback) {
  std::move(telemetry_callback_).Run(categories, std::move(callback));
}

}  // namespace wilco
}  // namespace diagnostics
