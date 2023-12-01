// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "metrics/fake_metrics_library.h"

using ::testing::ElementsAre;
using ::testing::IsEmpty;

class FakeMetricsLibraryTest : public testing::Test {
 public:
  FakeMetricsLibraryTest() = default;
  ~FakeMetricsLibraryTest() = default;

  FakeMetricsLibrary& lib() { return lib_; }

 private:
  FakeMetricsLibrary lib_;
};

TEST_F(FakeMetricsLibraryTest, Getters) {
  lib().SendToUMA("metric1", 1, 0, 100, 10);
  lib().SendToUMA("metric2", 1, 0, 100, 10);
  lib().SendToUMA("metric2", 2, 0, 100, 10);

  EXPECT_EQ(lib().NumCalls("metric0"), 0);
  EXPECT_EQ(lib().GetLast("metric0"), FakeMetricsLibrary::kInvalid);
  EXPECT_EQ(lib().NumCalls("metric1"), 1);
  EXPECT_EQ(lib().GetLast("metric1"), 1);
  EXPECT_EQ(lib().NumCalls("metric2"), 2);
  EXPECT_EQ(lib().GetLast("metric2"), 2);
}

TEST_F(FakeMetricsLibraryTest, SendToUMA) {
  lib().SendToUMA("metric1", 1, 0, 100, 10);
  lib().SendToUMA("metric2", 20, 0, 100, 10);
  lib().SendToUMA("metric2", 21, 0, 100, 10);

  EXPECT_EQ(lib().NumCalls("metric1"), 1);
  EXPECT_EQ(lib().GetLast("metric1"), 1);
  EXPECT_THAT(lib().GetCalls("metric1"), ElementsAre(1));

  EXPECT_EQ(lib().NumCalls("metric2"), 2);
  EXPECT_EQ(lib().GetLast("metric2"), 21);
  EXPECT_THAT(lib().GetCalls("metric2"), ElementsAre(20, 21));
}

TEST_F(FakeMetricsLibraryTest, SendEnumToUMA) {
  enum TestEnum {
    kMetricsValue1,
    kMetricsValue20,
    kMetricsValue21,
    kMetricsValueMax,
  };
  lib().SendEnumToUMA("metric1", kMetricsValue1, kMetricsValueMax);
  lib().SendEnumToUMA("metric2", kMetricsValue20, kMetricsValueMax);
  lib().SendEnumToUMA("metric2", kMetricsValue21, kMetricsValueMax);

  EXPECT_EQ(lib().NumCalls("metric1"), 1);
  EXPECT_EQ(lib().GetLast("metric1"), kMetricsValue1);
  EXPECT_THAT(lib().GetCalls("metric1"), ElementsAre(kMetricsValue1));

  EXPECT_EQ(lib().NumCalls("metric2"), 2);
  EXPECT_EQ(lib().GetLast("metric2"), kMetricsValue21);
  EXPECT_THAT(lib().GetCalls("metric2"),
              ElementsAre(kMetricsValue20, kMetricsValue21));
}

TEST_F(FakeMetricsLibraryTest, SendRepeatedEnumToUMA) {
  enum TestEnum {
    kMetricsValue1,
    kMetricsValue2,
    kMetricsValueMax,
  };
  lib().SendRepeatedEnumToUMA("metric", kMetricsValue1, kMetricsValueMax, 1);
  lib().SendRepeatedEnumToUMA("metric", kMetricsValue2, kMetricsValueMax, 2);
  lib().SendRepeatedEnumToUMA("metric", kMetricsValue1, kMetricsValueMax, 3);
  EXPECT_EQ(lib().NumCalls("metric"), 6);
  EXPECT_EQ(lib().GetLast("metric"), kMetricsValue1);
  EXPECT_THAT(lib().GetCalls("metric"), ElementsAre(0, 1, 1, 0, 0, 0));

  // Check max size.
  EXPECT_FALSE(lib().SendRepeatedEnumToUMA("metric", kMetricsValue2,
                                           kMetricsValueMax, 512));
  EXPECT_EQ(lib().GetLast("metric"), kMetricsValue1);
}

TEST_F(FakeMetricsLibraryTest, SendLinearToUMA) {
  lib().SendLinearToUMA("metric1", 1, 100);
  lib().SendLinearToUMA("metric2", 20, 100);
  lib().SendLinearToUMA("metric2", 21, 100);

  EXPECT_EQ(lib().NumCalls("metric1"), 1);
  EXPECT_EQ(lib().GetLast("metric1"), 1);
  EXPECT_THAT(lib().GetCalls("metric1"), ElementsAre(1));

  EXPECT_EQ(lib().NumCalls("metric2"), 2);
  EXPECT_EQ(lib().GetLast("metric2"), 21);
  EXPECT_THAT(lib().GetCalls("metric2"), ElementsAre(20, 21));
}

TEST_F(FakeMetricsLibraryTest, SendPercentageToUMA) {
  lib().SendPercentageToUMA("metric1", 1);
  lib().SendPercentageToUMA("metric2", 20);
  lib().SendPercentageToUMA("metric2", 21);

  EXPECT_EQ(lib().NumCalls("metric1"), 1);
  EXPECT_EQ(lib().GetLast("metric1"), 1);
  EXPECT_THAT(lib().GetCalls("metric1"), ElementsAre(1));

  EXPECT_EQ(lib().NumCalls("metric2"), 2);
  EXPECT_EQ(lib().GetLast("metric2"), 21);
  EXPECT_THAT(lib().GetCalls("metric2"), ElementsAre(20, 21));
}

TEST_F(FakeMetricsLibraryTest, SendBoolToUMA) {
  lib().SendBoolToUMA("metric1", true);
  lib().SendBoolToUMA("metric2", true);
  lib().SendBoolToUMA("metric2", false);

  EXPECT_EQ(lib().NumCalls("metric1"), 1);
  EXPECT_EQ(lib().GetLast("metric1"), true);
  EXPECT_THAT(lib().GetCalls("metric1"), ElementsAre(true));

  EXPECT_EQ(lib().NumCalls("metric2"), 2);
  EXPECT_EQ(lib().GetLast("metric2"), false);
  EXPECT_THAT(lib().GetCalls("metric2"), ElementsAre(true, false));
}

TEST_F(FakeMetricsLibraryTest, SendSparseToUMA) {
  lib().SendSparseToUMA("metric1", 1);
  lib().SendSparseToUMA("metric2", 20);
  lib().SendSparseToUMA("metric2", 21);

  EXPECT_EQ(lib().NumCalls("metric1"), 1);
  EXPECT_EQ(lib().GetLast("metric1"), 1);
  EXPECT_THAT(lib().GetCalls("metric1"), ElementsAre(1));

  EXPECT_EQ(lib().NumCalls("metric2"), 2);
  EXPECT_EQ(lib().GetLast("metric2"), 21);
  EXPECT_THAT(lib().GetCalls("metric2"), ElementsAre(20, 21));
}

TEST_F(FakeMetricsLibraryTest, Clear) {
  // Send an UMA, and ensure we can read it again.
  lib().SendToUMA("metric", 1, 0, 100, 10);
  EXPECT_EQ(lib().NumCalls("metric"), 1);
  EXPECT_EQ(lib().GetLast("metric"), 1);
  EXPECT_THAT(lib().GetCalls("metric"), ElementsAre(1));

  // Clear out all values, and ensure we don't see old UMA calls.
  lib().Clear();
  EXPECT_EQ(lib().NumCalls("metric"), 0);
  EXPECT_EQ(lib().GetLast("metric"), FakeMetricsLibrary::kInvalid);
  EXPECT_THAT(lib().GetCalls("metric"), IsEmpty());

  // We should still be able to add new metric values, though.
  lib().SendToUMA("metric", 2, 0, 100, 10);
  EXPECT_EQ(lib().NumCalls("metric"), 1);
  EXPECT_EQ(lib().GetLast("metric"), 2);
  EXPECT_THAT(lib().GetCalls("metric"), ElementsAre(2));
}
