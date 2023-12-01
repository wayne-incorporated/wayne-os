// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/metrics/state_metrics.h"

#include <map>
#include <utility>

#include <base/strings/string_number_conversions.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/metrics/metrics_constants.h"

namespace {

constexpr rmad::RmadState::StateCase kDefaultStateCase =
    rmad::RmadState::kRestock;
constexpr double kInitializeTimestamp = 1;
constexpr double kLeaveTimestamp = 3;

}  // namespace

namespace rmad {

class StateMetricsDataTest : public testing::Test {
 public:
  StateMetricsDataTest() = default;

  StateMetricsData CreateStateMetricsData() {
    StateMetricsData data;
    data.state_case = RmadState::STATE_NOT_SET;
    data.is_aborted = false;
    data.setup_timestamp = 0;
    data.overall_time = 0;
    data.transition_count = 0;
    data.get_log_count = 0;
    data.save_log_count = 0;
    return data;
  }

  base::Value CreateValue() {
    base::Value::Dict dict;
    dict.Set(kStateCase, 0);
    dict.Set(kStateIsAborted, false);
    dict.Set(kStateSetupTimestamp, 0.0);
    dict.Set(kStateOverallTime, 0.0);
    dict.Set(kStateTransitionsCount, 0);
    dict.Set(kStateGetLogCount, 0);
    dict.Set(kStateSaveLogCount, 0);
    return base::Value(std::move(dict));
  }
};

TEST_F(StateMetricsDataTest, OperatorIsEqual) {
  StateMetricsData data1 = CreateStateMetricsData();
  StateMetricsData data2 = CreateStateMetricsData();

  EXPECT_TRUE(data1 == data2);
}

TEST_F(StateMetricsDataTest, OperatorIsEqual_StateCaseNE) {
  StateMetricsData data1 = CreateStateMetricsData();
  StateMetricsData data2 = CreateStateMetricsData();

  data1.state_case = RmadState::kRestock;

  EXPECT_FALSE(data1 == data2);
}

TEST_F(StateMetricsDataTest, OperatorIsEqual_IsAbortedNE) {
  StateMetricsData data1 = CreateStateMetricsData();
  StateMetricsData data2 = CreateStateMetricsData();

  data1.is_aborted = true;

  EXPECT_FALSE(data1 == data2);
}

TEST_F(StateMetricsDataTest, OperatorIsEqual_SetupTimestampNE) {
  StateMetricsData data1 = CreateStateMetricsData();
  StateMetricsData data2 = CreateStateMetricsData();

  data1.setup_timestamp = 1;

  EXPECT_FALSE(data1 == data2);
}

TEST_F(StateMetricsDataTest, OperatorIsEqual_OverallTimeNE) {
  StateMetricsData data1 = CreateStateMetricsData();
  StateMetricsData data2 = CreateStateMetricsData();

  data1.overall_time = 1;

  EXPECT_FALSE(data1 == data2);
}

TEST_F(StateMetricsDataTest, OperatorIsEqual_GetLogCountNE) {
  StateMetricsData data1 = CreateStateMetricsData();
  StateMetricsData data2 = CreateStateMetricsData();

  data1.get_log_count = 1;

  EXPECT_FALSE(data1 == data2);
}

TEST_F(StateMetricsDataTest, OperatorIsEqual_SaveLogCountNE) {
  StateMetricsData data1 = CreateStateMetricsData();
  StateMetricsData data2 = CreateStateMetricsData();

  data1.save_log_count = 1;

  EXPECT_FALSE(data1 == data2);
}

TEST_F(StateMetricsDataTest, ToValue) {
  StateMetricsData data = CreateStateMetricsData();

  base::Value value = data.ToValue();

  EXPECT_EQ(value, CreateValue());
}

TEST_F(StateMetricsDataTest, ConvertToValue) {
  StateMetricsData data = CreateStateMetricsData();

  base::Value value = ConvertToValue(data);

  EXPECT_EQ(value, CreateValue());
}

TEST_F(StateMetricsDataTest, FromValue) {
  base::Value value = CreateValue();

  StateMetricsData data;
  EXPECT_TRUE(data.FromValue(&value));
  EXPECT_EQ(data, CreateStateMetricsData());
}

TEST_F(StateMetricsDataTest, FromValue_NoData) {
  base::Value* value = nullptr;
  StateMetricsData data;

  EXPECT_FALSE(data.FromValue(value));
}

TEST_F(StateMetricsDataTest, FromValue_ValueNotDict) {
  base::Value value(base::Value::Type::LIST);
  StateMetricsData data;

  EXPECT_FALSE(data.FromValue(&value));
}

TEST_F(StateMetricsDataTest, FromValue_NoStateCase) {
  base::Value value = CreateValue();
  StateMetricsData data;

  value.GetDict().Remove(kStateCase);
  EXPECT_FALSE(data.FromValue(&value));
}

TEST_F(StateMetricsDataTest, FromValue_NoTimeStamp) {
  base::Value value = CreateValue();
  StateMetricsData data;

  value.GetDict().Remove(kStateSetupTimestamp);
  EXPECT_FALSE(data.FromValue(&value));
}

TEST_F(StateMetricsDataTest, FromValue_NoOverallTime) {
  base::Value value = CreateValue();
  StateMetricsData data;

  value.GetDict().Remove(kStateOverallTime);
  EXPECT_FALSE(data.FromValue(&value));
}

TEST_F(StateMetricsDataTest, FromValue_NoIsAborted) {
  base::Value value = CreateValue();
  StateMetricsData data;

  value.GetDict().Remove(kStateIsAborted);
  EXPECT_FALSE(data.FromValue(&value));
}

TEST_F(StateMetricsDataTest, FromValue_NoTransitionsCount) {
  base::Value value = CreateValue();
  StateMetricsData data;

  value.GetDict().Remove(kStateTransitionsCount);
  EXPECT_FALSE(data.FromValue(&value));
}

TEST_F(StateMetricsDataTest, FromValue_NoGetLogCount) {
  base::Value value = CreateValue();
  StateMetricsData data;

  value.GetDict().Remove(kStateGetLogCount);
  EXPECT_FALSE(data.FromValue(&value));
}

TEST_F(StateMetricsDataTest, FromValue_NoSaveLogCount) {
  base::Value value = CreateValue();
  StateMetricsData data;

  value.GetDict().Remove(kStateSaveLogCount);
  EXPECT_FALSE(data.FromValue(&value));
}

TEST_F(StateMetricsDataTest, ConvertFromValue) {
  base::Value value = CreateValue();
  StateMetricsData data;

  EXPECT_TRUE(ConvertFromValue(&value, &data));
}

TEST_F(StateMetricsDataTest, ConvertFromValue_NoValue) {
  base::Value* value = nullptr;
  StateMetricsData data;

  EXPECT_FALSE(ConvertFromValue(value, &data));
}

TEST_F(StateMetricsDataTest, ConvertFromValue_NoData) {
  base::Value value = CreateValue();
  StateMetricsData* data = nullptr;

  EXPECT_TRUE(ConvertFromValue(&value, data));
}

class StateMetricsMapTest : public testing::Test {
 public:
  StateMetricsMapTest() = default;

  StateMetricsData CreateStateMetricsData() {
    StateMetricsData data;
    data.state_case = RmadState::STATE_NOT_SET;
    data.is_aborted = false;
    data.setup_timestamp = 0;
    data.overall_time = 1;
    data.transition_count = 2;
    data.get_log_count = 3;
    data.save_log_count = 4;
    return data;
  }

  StateMetricsMap CreateStateMetricsMap() {
    return StateMetricsMap(
        {{static_cast<int>(kInitialStateCase), CreateStateMetricsData()},
         {static_cast<int>(kDefaultStateCase), CreateStateMetricsData()}});
  }

  base::Value CreateValue() {
    base::Value::Dict state_dict;
    state_dict.Set(kStateCase, 0);
    state_dict.Set(kStateIsAborted, false);
    state_dict.Set(kStateSetupTimestamp, 0.0);
    state_dict.Set(kStateOverallTime, 1.0);
    state_dict.Set(kStateTransitionsCount, 2);
    state_dict.Set(kStateGetLogCount, 3);
    state_dict.Set(kStateSaveLogCount, 4);

    base::Value::Dict dict;
    dict.Set(base::NumberToString(static_cast<int>(kInitialStateCase)),
             state_dict.Clone());
    dict.Set(base::NumberToString(static_cast<int>(kDefaultStateCase)),
             std::move(state_dict));

    return base::Value(std::move(dict));
  }
};

TEST_F(StateMetricsMapTest, GetData) {
  StateMetricsMap map = CreateStateMetricsMap();
  StateMetricsData data = map[kDefaultStateCase];

  EXPECT_EQ(data, CreateStateMetricsData());
}

TEST_F(StateMetricsMapTest, GetConstData) {
  const StateMetricsMap map = CreateStateMetricsMap();
  StateMetricsData data = map[kDefaultStateCase];

  EXPECT_EQ(data, CreateStateMetricsData());
}

TEST_F(StateMetricsMapTest, InitializeState_UpdateStateOverallTime) {
  StateMetricsMap map = CreateStateMetricsMap();
  StateMetricsData data = CreateStateMetricsData();

  map.InitializeState(kDefaultStateCase, kInitializeTimestamp);
  data.state_case = kDefaultStateCase;
  data.setup_timestamp = kInitializeTimestamp;
  EXPECT_EQ(map[kDefaultStateCase], data);

  map.UpdateStateOverallTime(kDefaultStateCase, kLeaveTimestamp);
  data.setup_timestamp = kLeaveTimestamp;
  data.overall_time += (kLeaveTimestamp - kInitializeTimestamp);
  EXPECT_EQ(map[kDefaultStateCase], data);
}

TEST_F(StateMetricsMapTest,
       InitializeState_UpdateStateOverallTime_InitialState) {
  StateMetricsMap map = CreateStateMetricsMap();
  StateMetricsData data = CreateStateMetricsData();

  map.InitializeState(kInitialStateCase, kInitializeTimestamp);
  data.state_case = kInitialStateCase;
  data.setup_timestamp = kInitializeTimestamp;
  EXPECT_EQ(map[kInitialStateCase], data);

  map.UpdateStateOverallTime(kInitialStateCase, kLeaveTimestamp);
  data.setup_timestamp = kLeaveTimestamp;
  // Do not count the time spent on the initial state.
  data.overall_time += 0;
  EXPECT_EQ(map[kInitialStateCase], data);
}

TEST_F(StateMetricsMapTest, ConvertToValue) {
  StateMetricsMap map = CreateStateMetricsMap();

  base::Value value = ConvertToValue(map);

  EXPECT_EQ(value, CreateValue());
}

TEST_F(StateMetricsMapTest, ConvertFromValue) {
  base::Value value = CreateValue();
  StateMetricsMap map;

  EXPECT_TRUE(ConvertFromValue(&value, &map));
  EXPECT_EQ(map, CreateStateMetricsMap());
}

TEST_F(StateMetricsMapTest, ConvertFromValue_NoValue) {
  base::Value* value = nullptr;
  StateMetricsMap map;

  EXPECT_FALSE(ConvertFromValue(value, &map));
}

TEST_F(StateMetricsMapTest, ConvertFromValue_NoData) {
  base::Value value = CreateValue();
  StateMetricsMap* map = nullptr;

  EXPECT_TRUE(ConvertFromValue(&value, map));
}

}  // namespace rmad
