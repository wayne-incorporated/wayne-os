// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_METRICS_METRICS_H_
#define DISCOD_METRICS_METRICS_H_

#include <string>

namespace discod {

inline constexpr char kBurstResultHistogram[] = "Platform.Discod.BurstResult";
inline constexpr char kAutoWbBwUtilizationHistogram[] =
    "Platform.Discod.AutoWbBwUtilization";
inline constexpr char kAutoWbOnCyclesHistogram[] =
    "Platform.Discod.AutoWbOnCycles";
inline constexpr char kExplicitWbBwUtilizationHistogram[] =
    "Platform.Discod.ExplicitWbBwUtilization";
inline constexpr char kExplicitWbOnCyclesHistogram[] =
    "Platform.Discod.ExplicitWbOnCycles";

class Metrics {
 public:
  Metrics() = default;
  Metrics(const Metrics&) = delete;
  Metrics& operator=(const Metrics&) = delete;

  virtual ~Metrics() = default;

  virtual void SendToUMA(
      const std::string& name, int sample, int min, int max, int nbuckets) = 0;
  virtual void SendPercentageToUMA(const std::string& name, int sample) = 0;
  virtual void SendEnumToUMA(const std::string& name,
                             int sample,
                             int exclusive_max) = 0;
};

}  // namespace discod

#endif  // DISCOD_METRICS_METRICS_H_
