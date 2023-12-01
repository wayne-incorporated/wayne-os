// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCH_AGGREGATOR_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCH_AGGREGATOR_H_

#include <vector>

#include "diagnostics/cros_healthd/fetchers/backlight_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/battery_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/disk_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/fan_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/graphics_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/input_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/memory_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/network_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/stateful_partition_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/timezone_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/tpm_fetcher.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// This class is responsible for aggregating probe data from various fetchers,
// some of which may be asynchronous, and running the given callback when all
// probe data has been fetched.
class FetchAggregator final {
 public:
  explicit FetchAggregator(Context* context);
  FetchAggregator(const FetchAggregator&) = delete;
  FetchAggregator& operator=(const FetchAggregator&) = delete;
  ~FetchAggregator();

  // Runs the aggregator, which will collect all relevant data and then run the
  // callback.
  void Run(const std::vector<ash::cros_healthd::mojom::ProbeCategoryEnum>&
               categories_to_probe,
           ash::cros_healthd::mojom::CrosHealthdProbeService::
               ProbeTelemetryInfoCallback callback);

 private:
  BacklightFetcher backlight_fetcher_;
  BatteryFetcher battery_fetcher_;
  DiskFetcher disk_fetcher_;
  FanFetcher fan_fetcher_;
  GraphicsFetcher graphics_fetcher_;
  InputFetcher input_fetcher_;
  MemoryFetcher memory_fetcher_;
  NetworkFetcher network_fetcher_;
  StatefulPartitionFetcher stateful_partition_fetcher_;
  TimezoneFetcher timezone_fetcher_;
  TpmFetcher tpm_fetcher_;

  // The pointer to the Context object for accessing system utilities.
  Context* const context_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCH_AGGREGATOR_H_
