// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/power_profile.h"

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace typecd {

class PowerProfileTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    temp_dir_ = scoped_temp_dir_.GetPath();
  }

 public:
  base::FilePath temp_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

// Thin wrapper over PowerProfile. The only difference between this
// and the base class is CreatePdo() which we stub out.
class PowerProfileWrapper : public PowerProfile {
 public:
  explicit PowerProfileWrapper(const base::FilePath& path) : PowerProfile() {
    SetSyspath(path);
  }

 private:
  std::unique_ptr<Pdo> CreatePdo(const base::FilePath& path) override {
    // Create a dummy PDO. The contents don't matter as long as the index
    // is unique.
    return std::make_unique<Pdo>(path, Pdo::Type::kFixedSupply, index_++);
  }

  int index_;
};

// Test which checks that source and sink cap dirs are processed as expected.
TEST_F(PowerProfileTest, ParseDirs) {
  // Set up the sysfs directory structure.
  auto source_dir = temp_dir_.Append(std::string("source-capabilities"));
  ASSERT_TRUE(base::CreateDirectory(source_dir));

  ASSERT_TRUE(
      base::CreateDirectory(source_dir.Append(std::string("1:fixed_supply"))));
  // Directory name doesn't matter.
  ASSERT_TRUE(base::CreateDirectory(source_dir.Append(std::string("foo"))));
  // Files should be ignored.
  std::string foo2_file("foo2");
  ASSERT_TRUE(base::WriteFile(source_dir.Append(std::string("foo2")),
                              foo2_file.c_str(), foo2_file.length()));

  PowerProfileWrapper pp(temp_dir_);
  pp.ParseSourceCaps();

  EXPECT_EQ(2, pp.source_caps_.size());
}

}  // namespace typecd
