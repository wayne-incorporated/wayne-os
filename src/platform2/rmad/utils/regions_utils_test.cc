// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/regions_utils_impl.h"

#include <memory>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace rmad {

constexpr char kRegionsFileName[] = "json_store_file";
constexpr char kWrongRegionsFileName[] = "wrong_file_name";
constexpr char kCrosRegionsJson[] =
    R"({
      "test1": {
        "region_code": "test1",
        "confirmed": true,
        "description": "Test1",
        "regulatory_domain": "TEST1"
      },
      "test2": {
        "region_code": "test2",
        "confirmed": true,
        "description": "Test2",
        "regulatory_domain": "TEST2"
      },
      "test3": {
        "region_code": "test3",
        "confirmed": false,
        "description": "Test3",
        "regulatory_domain": "TEST3"
      }
    })";
const std::vector<std::string> kCrosRegionList = {"test1", "test2"};

class RegionsUtilsImplTest : public testing::Test {
 public:
  RegionsUtilsImplTest() {}

  base::FilePath CreateInputFile(const std::string& filename,
                                 const char* str,
                                 int size) {
    base::FilePath file_path = temp_dir_.GetPath().AppendASCII(filename);
    base::WriteFile(file_path, str, size);
    return file_path;
  }

  std::unique_ptr<RegionsUtils> CreateRegionsUtils(
      const base::FilePath& file_path) {
    return std::make_unique<RegionsUtilsImpl>(file_path);
  }

 protected:
  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  base::ScopedTempDir temp_dir_;
};

TEST_F(RegionsUtilsImplTest, GetRegionList_Success) {
  auto file_path = CreateInputFile(kRegionsFileName, kCrosRegionsJson,
                                   std::size(kCrosRegionsJson) - 1);
  auto regions_utils = CreateRegionsUtils(file_path);

  std::vector<std::string> region_list;
  EXPECT_TRUE(regions_utils->GetRegionList(&region_list));
  EXPECT_EQ(region_list, kCrosRegionList);
}

TEST_F(RegionsUtilsImplTest, GetRegionList_WrongFileNameFailed) {
  auto file_path = CreateInputFile(kRegionsFileName, kCrosRegionsJson,
                                   std::size(kCrosRegionsJson) - 1);
  auto regions_utils = CreateRegionsUtils(
      temp_dir_.GetPath().AppendASCII(kWrongRegionsFileName));

  std::vector<std::string> region_list;
  EXPECT_FALSE(regions_utils->GetRegionList(&region_list));
  // If we cannot get the possible regions, we leave the |region_list|
  // untouched.
  EXPECT_EQ(region_list, std::vector<std::string>());
}

TEST_F(RegionsUtilsImplTest, GetRegionList_WrongContentFailed) {
  auto file_path = CreateInputFile(kRegionsFileName, kCrosRegionsJson,
                                   std::size(kCrosRegionsJson) - 100);
  auto regions_utils = CreateRegionsUtils(file_path);

  std::vector<std::string> region_list;
  EXPECT_FALSE(regions_utils->GetRegionList(&region_list));
  // If we cannot get the possible regions, we leave the |region_list|
  // untouched.
  EXPECT_EQ(region_list, std::vector<std::string>());
}

}  // namespace rmad
