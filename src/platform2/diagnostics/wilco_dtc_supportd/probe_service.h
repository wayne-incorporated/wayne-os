// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_PROBE_SERVICE_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_PROBE_SERVICE_H_

#include <vector>

#include <base/functional/callback.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>

#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace wilco {

// The probe service is responsible for getting telemetry information.
class ProbeService {
 public:
  using ProbeTelemetryInfoCallback =
      base::OnceCallback<void(ash::cros_healthd::mojom::TelemetryInfoPtr)>;

  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Binds |service| to an implementation of CrosHealthdProbeService. In
    // production, the implementation is provided by cros_healthd. Returns
    // whether binding is successful.
    virtual bool BindCrosHealthdProbeService(
        mojo::PendingReceiver<ash::cros_healthd::mojom::CrosHealthdProbeService>
            service) = 0;
  };

  virtual ~ProbeService() = default;

  // Requests telemetry info for categories.
  virtual void ProbeTelemetryInfo(
      std::vector<ash::cros_healthd::mojom::ProbeCategoryEnum> categories,
      ProbeTelemetryInfoCallback callback) = 0;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_PROBE_SERVICE_H_
