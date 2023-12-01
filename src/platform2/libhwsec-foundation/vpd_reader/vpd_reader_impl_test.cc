// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/vpd_reader/vpd_reader_impl.h"

#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace hwsec_foundation {

namespace {

constexpr char kFakeKey[] = "vpd_key";
constexpr char kFakeMissingKey[] = "missing_vpd_key";
constexpr char kFakeValue[] = "vpd_value";

class ScopedFakeVpdEntry {
 public:
  ScopedFakeVpdEntry(const std::string& key, const std::string& value) {
    [this](const std::string& key, const std::string& value) {
      ASSERT_TRUE(dir_.CreateUniqueTempDir());
      path_ = dir_.GetPath().Append(key);
      ASSERT_TRUE(base::WriteFile(path_, value));
    }(key, value);
  }
  ~ScopedFakeVpdEntry() = default;
  base::FilePath path() const { return path_; }

 private:
  base::ScopedTempDir dir_;
  base::FilePath path_;
};

}  // namespace

namespace {

TEST(VpdReaderImplTest, GetSuccess) {
  ScopedFakeVpdEntry entry(kFakeKey, kFakeValue);
  VpdReaderImpl reader(entry.path().DirName().value());
  const std::optional<std::string> result = reader.Get(kFakeKey);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), kFakeValue);
}

TEST(VpdReaderImplTest, GetSuccessEmptyValue) {
  ScopedFakeVpdEntry entry(kFakeKey, "");
  VpdReaderImpl reader(entry.path().DirName().value());
  const std::optional<std::string> result = reader.Get(kFakeKey);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), "");
}

TEST(VpdReaderImplTest, GetErrorNoKey) {
  ScopedFakeVpdEntry entry(kFakeKey, kFakeValue);
  VpdReaderImpl reader(entry.path().DirName().value());
  const std::optional<std::string> result = reader.Get(kFakeMissingKey);
  EXPECT_FALSE(result.has_value());
}

TEST(VpdReaderImplTest, GetErrorRead) {
  ScopedFakeVpdEntry entry(kFakeKey, kFakeValue);
  ASSERT_TRUE(base::SetPosixFilePermissions(entry.path(), 0));
  VpdReaderImpl reader(entry.path().DirName().value());
  const std::optional<std::string> result = reader.Get(kFakeKey);
  ASSERT_FALSE(result.has_value());
}

}  // namespace

}  // namespace hwsec_foundation
