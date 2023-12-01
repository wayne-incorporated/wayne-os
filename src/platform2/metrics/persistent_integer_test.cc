// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <gtest/gtest.h>

#include <base/check.h>
#include <base/compiler_specific.h>
#include <base/files/scoped_temp_dir.h>

#include "metrics/persistent_integer.h"

using chromeos_metrics::PersistentInteger;

class PersistentIntegerTest : public testing::Test {};

TEST_F(PersistentIntegerTest, BasicChecks) {
  base::ScopedTempDir temp_dir;
  CHECK(temp_dir.CreateUniqueTempDir());
  const base::FilePath backing_path = temp_dir.GetPath().Append("xyz");
  auto pi = std::make_unique<PersistentInteger>(backing_path);

  // Test initialization.
  EXPECT_EQ(0, pi->Get());

  // Test set and add.
  pi->Set(2);
  pi->Add(3);
  EXPECT_EQ(5, pi->Get());

  // Test max.
  pi->Set(4);
  pi->Max(5);
  EXPECT_EQ(5, pi->Get());
  pi->Max(2);
  EXPECT_EQ(5, pi->Get());

  // Test persistence.
  pi.reset(new PersistentInteger(backing_path));
  EXPECT_EQ(5, pi->Get());

  // Test GetAndClear.
  EXPECT_EQ(5, pi->GetAndClear());
  EXPECT_EQ(pi->Get(), 0);

  // Another persistence test.
  pi.reset(new PersistentInteger(backing_path));
  EXPECT_EQ(0, pi->Get());
}
