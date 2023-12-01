// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/util/dynamic_flag.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace reporting {
namespace {

class TestFlagDerived : public DynamicFlag {
 public:
  explicit TestFlagDerived(bool is_enabled)
      : DynamicFlag("test_flag", is_enabled) {}

  MOCK_METHOD(void, OnValueUpdate, (bool is_enabled), (override));
};

class TestFlagAggregated {
 public:
  explicit TestFlagAggregated(bool is_enabled)
      : flag_("test_flag", is_enabled, /*owner=*/this) {}

  bool is_enabled() const { return flag_.is_enabled(); }

  void SetValue(bool is_enabled) { flag_.SetValue(is_enabled); }

  MOCK_METHOD(void, OnEmbeddedValueUpdate, (bool is_enabled), (const));

 private:
  class EmbeddedFlag : public DynamicFlag {
   public:
    EmbeddedFlag(base::StringPiece name,
                 bool is_enabled,
                 TestFlagAggregated* owner)
        : DynamicFlag(name, is_enabled), owner_(owner) {
      DCHECK(owner);
    }

   private:
    void OnValueUpdate(bool is_enabled) override {
      owner_->OnEmbeddedValueUpdate(is_enabled);
    }

    TestFlagAggregated* const owner_;
  };

  EmbeddedFlag flag_;
};

TEST(DerivedFlagTest, OnAndOff) {
  TestFlagDerived flag(/*is_enabled=*/true);
  EXPECT_TRUE(flag.is_enabled());
  EXPECT_CALL(flag, OnValueUpdate).Times(0);
  flag.SetValue(/*is_enabled=*/true);  // same
  EXPECT_TRUE(flag.is_enabled());
  EXPECT_CALL(flag, OnValueUpdate(false)).Times(1);
  flag.SetValue(/*is_enabled=*/false);  // flip
  EXPECT_FALSE(flag.is_enabled());
}

TEST(DerivedFlagTest, OffAndOn) {
  TestFlagDerived flag(/*is_enabled=*/false);
  EXPECT_FALSE(flag.is_enabled());
  EXPECT_CALL(flag, OnValueUpdate).Times(0);
  flag.SetValue(/*is_enabled=*/false);  // same
  EXPECT_FALSE(flag.is_enabled());
  EXPECT_CALL(flag, OnValueUpdate(true)).Times(1);
  flag.SetValue(/*is_enabled=*/true);  // flip
  EXPECT_TRUE(flag.is_enabled());
}

TEST(AggregatedFlagTest, OnAndOff) {
  TestFlagAggregated flag(/*is_enabled=*/true);
  EXPECT_TRUE(flag.is_enabled());
  EXPECT_CALL(flag, OnEmbeddedValueUpdate).Times(0);
  flag.SetValue(/*is_enabled=*/true);  // same
  EXPECT_TRUE(flag.is_enabled());
  EXPECT_CALL(flag, OnEmbeddedValueUpdate(false)).Times(1);
  flag.SetValue(/*is_enabled=*/false);  // flip
  EXPECT_FALSE(flag.is_enabled());
}

TEST(AggregatedFlagTest, OffAndOn) {
  TestFlagAggregated flag(/*is_enabled=*/false);
  EXPECT_FALSE(flag.is_enabled());
  EXPECT_CALL(flag, OnEmbeddedValueUpdate).Times(0);
  flag.SetValue(/*is_enabled=*/false);  // same
  EXPECT_FALSE(flag.is_enabled());
  EXPECT_CALL(flag, OnEmbeddedValueUpdate(true)).Times(1);
  flag.SetValue(/*is_enabled=*/true);  // flip
  EXPECT_TRUE(flag.is_enabled());
}
}  // namespace
}  // namespace reporting
