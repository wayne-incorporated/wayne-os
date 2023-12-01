// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_benchmark/json_serializer.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <utility>

#include <base/check.h>

using chrome::ml_benchmark::BenchmarkResults;
using chrome::ml_benchmark::Metric;
using ::testing::Eq;
using ::testing::Pointee;

namespace ml_benchmark {

TEST(BenchmarkResultsToJson, Basics) {
  BenchmarkResults results;
  results.set_status(chrome::ml_benchmark::RUNTIME_ERROR);
  results.set_results_message("Test error");

  const std::optional<base::Value::Dict> json =
      ml_benchmark::BenchmarkResultsToJson(results);
  ASSERT_TRUE(json);
  EXPECT_EQ(json->FindInt("status"), chrome::ml_benchmark::RUNTIME_ERROR);
  EXPECT_THAT(json->FindString("results_message"), Pointee(Eq("Test error")));
}

TEST(BenchmarkResultsToJson, Percentiles) {
  BenchmarkResults results;
  auto& latency_map = *results.mutable_percentile_latencies_in_us();
  latency_map[50] = 1000;
  latency_map[90] = 2000;
  latency_map[95] = 3000;
  latency_map[99] = 4000;

  const std::optional<base::Value::Dict> json =
      ml_benchmark::BenchmarkResultsToJson(results);
  ASSERT_TRUE(json);
  const base::Value::Dict* latencies =
      json->FindDict("percentile_latencies_in_us");
  ASSERT_TRUE(json);
  EXPECT_EQ(latencies->FindInt("50"), 1000);
  EXPECT_EQ(latencies->FindInt("90"), 2000);
  EXPECT_EQ(latencies->FindInt("95"), 3000);
  EXPECT_EQ(latencies->FindInt("99"), 4000);
}

TEST(BenchmarkResultsToJson, Metrics) {
  BenchmarkResults results;

  {
    Metric* m = results.add_metrics();
    m->set_name("Multiple ms metric");
    m->set_units(Metric::MS);
    m->set_cardinality(Metric::MULTIPLE);

    m->add_values(1);
    m->add_values(2);
    m->add_values(3);
  }

  {
    Metric* m = results.add_metrics();
    m->set_name("Single unitless metric");
    m->set_direction(Metric::BIGGER_IS_BETTER);
    // UNITLESS + Cardinality::SINGLE by default.
    m->add_values(42);
  }

  const std::optional<base::Value::Dict> json =
      ml_benchmark::BenchmarkResultsToJson(results);
  ASSERT_TRUE(json);
  const base::Value::List* metrics = json->FindList("metrics");
  EXPECT_EQ(metrics->size(), 2);

  {
    assert((*metrics)[0].is_dict());
    const auto& m = (*metrics)[0].GetDict();
    EXPECT_THAT(m.FindString("name"), Pointee(Eq("Multiple ms metric")));
    EXPECT_THAT(m.FindString("units"), Pointee(Eq("ms")));
    EXPECT_THAT(m.FindString("improvement_direction"),
                Pointee(Eq("smaller_is_better")));
    EXPECT_THAT(m.FindString("cardinality"), Pointee(Eq("multiple")));

    const base::Value::List* values = m.FindList("values");
    ASSERT_TRUE(values);
    EXPECT_EQ(values->size(), 3);
    EXPECT_EQ((*values)[0].GetIfDouble(), 1);
    EXPECT_EQ((*values)[1].GetIfDouble(), 2);
    EXPECT_EQ((*values)[2].GetIfDouble(), 3);
  }

  {
    assert((*metrics)[1].is_dict());
    const auto& m = (*metrics)[1].GetDict();
    EXPECT_THAT(m.FindString("name"), Pointee(Eq("Single unitless metric")));
    EXPECT_THAT(m.FindString("units"), Pointee(Eq("unitless")));
    EXPECT_THAT(m.FindString("improvement_direction"),
                Pointee(Eq("bigger_is_better")));
    EXPECT_THAT(m.FindString("cardinality"), Pointee(Eq("single")));

    const base::Value::List* values = m.FindList("values");
    ASSERT_TRUE(values);
    EXPECT_EQ(values->size(), 1);
    EXPECT_EQ((*values)[0].GetIfDouble(), 42);
  }
}

TEST(BenchmarkResultsToJson, MetricsCardinality) {
  auto get_metrics_size =
      [](const BenchmarkResults& results) -> std::optional<size_t> {
    const std::optional<base::Value::Dict> json =
        ml_benchmark::BenchmarkResultsToJson(results);
    if (!json)
      return std::nullopt;

    const base::Value::List* metrics = json->FindList("metrics");
    CHECK(metrics);
    CHECK(!metrics->empty());
    CHECK((*metrics)[0].is_dict());
    const auto& m = (*metrics)[0].GetDict();
    const base::Value::List* values = m.FindList("values");
    CHECK(values);
    return values->size();
  };

  {
    BenchmarkResults results;
    Metric* m = results.add_metrics();
    m->set_cardinality(Metric::MULTIPLE);
    m->add_values(1);
    m->add_values(2);
    m->add_values(3);
    EXPECT_EQ(get_metrics_size(results), 3);
  }

  {
    BenchmarkResults results;
    Metric* m = results.add_metrics();
    m->set_cardinality(Metric::MULTIPLE);
    // No results is OK here.
    EXPECT_EQ(get_metrics_size(results), 0);
  }

  {
    BenchmarkResults results;
    Metric* m = results.add_metrics();
    m->set_cardinality(Metric::SINGLE);
    m->add_values(1);
    EXPECT_EQ(get_metrics_size(results), 1);
  }

  {
    BenchmarkResults results;
    Metric* m = results.add_metrics();
    m->set_cardinality(Metric::SINGLE);
    // Three results instead of a single one is not OK.
    m->add_values(1);
    m->add_values(2);
    m->add_values(3);
    EXPECT_EQ(get_metrics_size(results), std::nullopt);
  }

  {
    BenchmarkResults results;
    Metric* m = results.add_metrics();
    m->set_cardinality(Metric::SINGLE);
    // No results instead of a single one is not OK.
    EXPECT_EQ(get_metrics_size(results), std::nullopt);
  }
}

TEST(BenchmarkResultsToJson, PowerNormalizationFactor) {
  BenchmarkResults results;
  results.set_power_normalization_factor(100);

  const std::optional<base::Value::Dict> json =
      ml_benchmark::BenchmarkResultsToJson(results);
  ASSERT_TRUE(json);
  EXPECT_EQ(json->FindDouble("power_normalization_factor"), 100);
}

}  // namespace ml_benchmark
