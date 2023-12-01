// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_benchmark/json_serializer.h"

#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/values.h>
#include <brillo/file_utils.h>

#include <optional>
#include <string>
#include <utility>

using chrome::ml_benchmark::BenchmarkResults;
using chrome::ml_benchmark::Metric;

namespace {

// Maps to |tast/common/perf/perf.go| |supportedUnits|.
std::optional<std::string> metric_units(const Metric::Units u) {
  switch (u) {
    case Metric::UNITLESS:
      return "unitless";
    case Metric::BYTES:
      return "bytes";
    case Metric::JOULES:
      return "J";
    case Metric::WATTS:
      return "W";
    case Metric::COUNT:
      return "count";
    case Metric::MS:
      return "ms";
    case Metric::NPERCENT:
      return "n%";
    case Metric::SIGMA:
      return "sigma";
    case Metric::TS_MS:
      return "tsMs";
    default:
      LOG(ERROR) << "Unhandled unit: " << u;
      return std::nullopt;
  }
}

// Maps to |mlbenchmark/scenario.go| |ImprovementDirection|.
std::optional<std::string> metric_direction(const Metric::Direction d) {
  switch (d) {
    case Metric::SMALLER_IS_BETTER:
      return "smaller_is_better";
    case Metric::BIGGER_IS_BETTER:
      return "bigger_is_better";
    default:
      LOG(ERROR) << "Unhandled direction: " << d;
      return std::nullopt;
  }
}

// Maps to |mlbenchmark/scenario.go| |Cardinality|.
std::optional<std::string> metric_cardinality(const Metric::Cardinality c) {
  switch (c) {
    case Metric::SINGLE:
      return "single";
    case Metric::MULTIPLE:
      return "multiple";
    default:
      LOG(ERROR) << "Unhandled cardinality: " << c;
      return std::nullopt;
  }
}

}  // namespace

namespace ml_benchmark {

std::optional<base::Value::Dict> BenchmarkResultsToJson(
    const BenchmarkResults& results) {
  base::Value::Dict doc;
  doc.Set("status", results.status());
  doc.Set("results_message", results.results_message());
  if (results.status() != chrome::ml_benchmark::OK) {
    return doc;
  }

  base::Value::Dict percentiles;
  for (const auto& latencies : results.percentile_latencies_in_us()) {
    std::string percentile = std::to_string(latencies.first);
    percentiles.Set(percentile, static_cast<int>(latencies.second));
  }
  doc.Set("percentile_latencies_in_us", std::move(percentiles));

  base::Value::List metrics;
  for (const auto& m : results.metrics()) {
    base::Value::Dict metric;
    metric.Set("name", m.name());
    const auto direction = metric_direction(m.direction());
    if (!direction)
      return std::nullopt;
    metric.Set("improvement_direction", *direction);
    const auto units = metric_units(m.units());
    if (!units)
      return std::nullopt;
    metric.Set("units", *units);
    const auto cardinality = metric_cardinality(m.cardinality());
    if (!cardinality)
      return std::nullopt;
    metric.Set("cardinality", *cardinality);

    if (m.cardinality() == Metric::SINGLE && m.values().size() != 1) {
      LOG(ERROR) << "Single cardinality metrics should contain a single value. "
                 << m.values().size() << " values found instead for metric "
                 << m.name();
      return std::nullopt;
    }
    base::Value::List values;
    for (const auto& v : m.values()) {
      values.Append(v);
    }
    metric.Set("values", std::move(values));

    metrics.Append(std::move(metric));
  }
  doc.Set("metrics", std::move(metrics));

  doc.Set("power_normalization_factor", results.power_normalization_factor());

  return doc;
}

void WriteResultsToPath(const BenchmarkResults& results,
                        const base::FilePath& output_path) {
  std::optional<base::Value::Dict> doc = BenchmarkResultsToJson(results);
  if (!doc) {
    return;
  }

  std::string results_string;
  if (!base::JSONWriter::Write(*doc, &results_string)) {
    LOG(ERROR) << "Unable to serialize benchmarking results.";
    return;
  }
  constexpr mode_t kFileRWMode = 0644;
  if (!brillo::WriteToFileAtomic(output_path, results_string.c_str(),
                                 results_string.size(), kFileRWMode)) {
    LOG(ERROR) << "Unable to write out the benchmarking results";
  }
}

}  // namespace ml_benchmark
