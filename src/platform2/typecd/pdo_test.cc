// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/pdo.h"

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace typecd {

class PdoTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    temp_dir_ = scoped_temp_dir_.GetPath();
  }

 public:
  base::FilePath temp_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

// Test which checks that the PDO directory has a valid type name and index.
TEST_F(PdoTest, ParseType) {
  auto pdo_path = temp_dir_.Append(std::string("1:fixed_supply"));
  ASSERT_TRUE(base::CreateDirectory(pdo_path));
  auto pdo = Pdo::MakePdo(pdo_path);
  EXPECT_TRUE(pdo);

  pdo_path = temp_dir_.Append(std::string("2:variable_supply"));
  ASSERT_TRUE(base::CreateDirectory(pdo_path));
  pdo = Pdo::MakePdo(pdo_path);
  EXPECT_TRUE(pdo);

  pdo_path = temp_dir_.Append(std::string("7:battery"));
  ASSERT_TRUE(base::CreateDirectory(pdo_path));
  pdo = Pdo::MakePdo(pdo_path);
  EXPECT_TRUE(pdo);

  pdo_path = temp_dir_.Append(std::string("4:programmable_supply"));
  ASSERT_TRUE(base::CreateDirectory(pdo_path));
  pdo = Pdo::MakePdo(pdo_path);
  EXPECT_TRUE(pdo);

  // Invalid index should prevent object creation.
  pdo_path = temp_dir_.Append(std::string("8:fixed_supply"));
  ASSERT_TRUE(base::CreateDirectory(pdo_path));
  pdo = Pdo::MakePdo(pdo_path);
  EXPECT_FALSE(pdo);

  // Invalid type should prevent object creation.
  pdo_path = temp_dir_.Append(std::string("3:foo"));
  ASSERT_TRUE(base::CreateDirectory(pdo_path));
  pdo = Pdo::MakePdo(pdo_path);
  EXPECT_FALSE(pdo);
}

}  // namespace typecd
