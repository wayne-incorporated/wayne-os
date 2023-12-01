// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BATTERY_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BATTERY_FETCHER_H_

#include <optional>
#include <string>
#include <vector>

#include "diagnostics/cros_healthd/fetchers/base_fetcher.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// The BatteryFetcher class is responsible for gathering battery info reported
// by cros_healthd. Some info is fetched via powerd, while Smart Battery info
// is collected from ectool via debugd.
class BatteryFetcher final : public BaseFetcher {
 public:
  using BaseFetcher::BaseFetcher;

  // Returns a structure with either the device's battery info or the error that
  // occurred fetching the information.
  ash::cros_healthd::mojom::BatteryResultPtr FetchBatteryInfo();

 private:
  using OptionalProbeErrorPtr =
      std::optional<ash::cros_healthd::mojom::ProbeErrorPtr>;

  // Populates general battery data fields in |info| obtained from the provided
  // |power_supply_proto|. Returns std::nullopt on success or a ProbeError
  // on failure.
  OptionalProbeErrorPtr PopulateBatteryInfoFromPowerdResponse(
      const power_manager::PowerSupplyProperties& power_supply_proto,
      ash::cros_healthd::mojom::BatteryInfo* info);

  // Populates the Smart Battery fields in |info| obtained by using ectool
  // via debugd. Returns std::nullopt on success or a ProbeError on failure.
  OptionalProbeErrorPtr PopulateSmartBatteryInfo(
      ash::cros_healthd::mojom::BatteryInfo* info);

  // Populates |metric_value| with the value obtained from requesting
  // |metric_name| from ectool via debugd. Returns std::nullopt on success or a
  // ProbeError on failure.
  template <typename T>
  OptionalProbeErrorPtr GetSmartBatteryMetric(
      const std::string& metric_name,
      base::OnceCallback<bool(const base::StringPiece& input, T* output)>
          convert_string_to_num,
      T* metric_value);
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BATTERY_FETCHER_H_
