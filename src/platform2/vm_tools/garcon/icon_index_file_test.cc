// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/scoped_temp_dir.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <gtest/gtest.h>

#include "vm_tools/garcon/icon_index_file.h"

namespace vm_tools {
namespace garcon {

namespace {

class IconIndexFileTest : public ::testing::Test {
 public:
  IconIndexFileTest() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    icon_theme_dir_ = temp_dir_.GetPath();
  }
  IconIndexFileTest(const IconIndexFileTest&) = delete;
  IconIndexFileTest& operator=(const IconIndexFileTest&) = delete;

  ~IconIndexFileTest() override = default;

  base::FilePath WriteIndexThemeFile(const std::string& contents) {
    base::FilePath file_path = icon_theme_dir_.Append("index.theme");
    EXPECT_EQ(contents.size(),
              base::WriteFile(file_path, contents.c_str(), contents.size()));
    return file_path;
  }

  void ValidateIndexThemeFile(
      const std::string& contents,
      int icon_size,
      int scale,
      const std::vector<base::FilePath>& expected_result) {
    WriteIndexThemeFile(contents);
    std::vector<base::FilePath> actual_result;
    std::unique_ptr<IconIndexFile> icon_index_file =
        IconIndexFile::ParseIconIndexFile(icon_theme_dir_);
    if (icon_index_file) {
      actual_result =
          icon_index_file->GetPathsForSizeAndScale(icon_size, scale);
    }
    EXPECT_TRUE(expected_result == actual_result);
  }

  base::FilePath icon_theme_dir() { return icon_theme_dir_; }

 private:
  base::ScopedTempDir temp_dir_;
  base::FilePath icon_theme_dir_;
};

}  // namespace

// This test verifies that an empty index.theme file results in empty
// directories.
TEST_F(IconIndexFileTest, EmptyIndexFile) {
  ValidateIndexThemeFile("", 48, 1, {});
}

// This test verifies that if a directory is not listed in the icon theme
// section then it's not returned.
TEST_F(IconIndexFileTest, DirectoryNotListed) {
  ValidateIndexThemeFile(
      "[Icon Theme]\n"
      "Name=Hicolor\n"
      "Comment=Fallback icon theme\n"
      "Hidden=true\n"
      "Directories=48x48@2/apps\n"
      "\n\n"
      "[48x48/apps]\n"
      "Size=48\n"
      "Context=Applications\n"
      "Type=Threshold\n",
      48, 1, {});
}

// This test verifies that correct directory is returned when there is only one
// directory listed in index.theme file.
TEST_F(IconIndexFileTest, OneDirectoryOnly) {
  ValidateIndexThemeFile(
      "[Icon Theme]\n"
      "Name=Hicolor\n"
      "Comment=Fallback icon theme\n"
      "Hidden=true\n"
      "Directories=48x48/apps\n"
      "\n\n"
      "[48x48/apps]\n"
      "Size=48\n"
      "Context=Applications\n"
      "Type=Threshold\n",
      48, 1, {icon_theme_dir().Append("48x48").Append("apps")});
}

// This test verifies that directory sections with unreasonable values are
// ignored.
TEST_F(IconIndexFileTest, UnreasonableValueSectionsIgnored) {
  ValidateIndexThemeFile(
      "[Icon Theme]\n"
      "Name=Hicolor\n"
      "Comment=Fallback icon theme\n"
      "Hidden=true\n"
      "Directories=48x48@2/apps,96x96/apps,128x128/apps\n"
      "\n\n"
      "[48x48@2/apps]\n"
      "Size=48\n"
      "Scale=50000\n"
      "Context=Applications\n"
      "Type=Threshold\n\n"
      "[96x96/apps]\n"
      "Size=96\n"
      "Context=Applications\n"
      "Type=Threshold\n\n"
      "[128x128/apps]\n"
      "Size=-234\n"
      "Context=Applications\n"
      "Type=Threshold\n",
      96, 1, {icon_theme_dir().Append("96x96").Append("apps")});
}

// This test verifies that the perfect matched directory is in front.
TEST_F(IconIndexFileTest, PerfectMatchInFront) {
  ValidateIndexThemeFile(
      "[Icon Theme]\n"
      "Name=Hicolor\n"
      "Comment=Fallback icon theme\n"
      "Hidden=true\n"
      "Directories=48x48@2/apps,96x96/apps\n"
      "\n\n"
      "[48x48@2/apps]\n"
      "Size=48\n"
      "Scale=2\n"
      "Context=Applications\n"
      "Type=Threshold\n\n"
      "[96x96/apps]\n"
      "Size=96\n"
      "Context=Applications\n"
      "Type=Threshold\n",
      96, 1,
      {icon_theme_dir().Append("96x96").Append("apps"),
       icon_theme_dir().Append("48x48@2").Append("apps")});
}

// This test verifies that the logrithmic distance is used.
TEST_F(IconIndexFileTest, LogrithmicDistance) {
  ValidateIndexThemeFile(
      "[Icon Theme]\n"
      "Name=Hicolor\n"
      "Comment=Fallback icon theme\n"
      "Hidden=true\n"
      "Directories=12x12/apps,40x40/apps\n"
      "\n\n"
      "[12x12/apps]\n"
      "Size=12\n"
      "Context=Applications\n"
      "Type=Threshold\n\n"
      "[40x40/apps]\n"
      "Size=40\n"
      "Context=Applications\n"
      "Type=Threshold\n",
      24, 1,
      {icon_theme_dir().Append("40x40").Append("apps"),
       icon_theme_dir().Append("12x12").Append("apps")});
}

// This test verifies that a directory which is within limit is in front of
// one that's not within limit even though its distance is farther.
TEST_F(IconIndexFileTest, WithinLimitIsInFront) {
  ValidateIndexThemeFile(
      "[Icon Theme]\n"
      "Name=Hicolor\n"
      "Comment=Fallback icon theme\n"
      "Hidden=true\n"
      "Directories=12x12/apps,40x40/apps\n"
      "\n\n"
      "[12x12/apps]\n"
      "Size=12\n"
      "Context=Applications\n"
      "Type=Threshold\n\n"
      "[40x40/apps]\n"
      "Size=40\n"
      "Context=Applications\n"
      "Type=Fixed\n",
      24, 1,
      {icon_theme_dir().Append("12x12").Append("apps"),
       icon_theme_dir().Append("40x40").Append("apps")});
}

// This test verifies that a perfect match is in front of one that's not perfect
// match but within limit, which in turn is in front of one that's not within
// limit.
TEST_F(IconIndexFileTest, PerfectThenWithinLimitThenOther) {
  ValidateIndexThemeFile(
      "[Icon Theme]\n"
      "Name=Hicolor\n"
      "Comment=Fallback icon theme\n"
      "Hidden=true\n"
      "Directories=12x12@2/apps,40x40/apps,24x24/apps\n"
      "\n\n"
      "[12x12@2/apps]\n"
      "Size=12\n"
      "Scale=2\n"
      "Context=Applications\n"
      "Type=Threshold\n\n"
      "[40x40/apps]\n"
      "Size=40\n"
      "Context=Applications\n"
      "Type=Scalable\n"
      "[24x24/apps]\n"
      "Size=24\n"
      "Context=Applications\n"
      "Type=Fixed\n",
      24, 1,
      {icon_theme_dir().Append("24x24").Append("apps"),
       icon_theme_dir().Append("12x12@2").Append("apps"),
       icon_theme_dir().Append("40x40").Append("apps")});
}

// This test verifies that distance is zero between the same size and scale.
TEST_F(IconIndexFileTest, BasicZeroDistance) {
  IconIndexFile::DirectoryEntry directory_entry = {.size = 48, .scale = 2};
  EXPECT_EQ(0, IconIndexFile::Distance(directory_entry, 48, 2));
}

// This test verifies that distance is zero when the scaled size matches.
TEST_F(IconIndexFileTest, ScaledZeroDistance) {
  IconIndexFile::DirectoryEntry directory_entry = {.size = 48, .scale = 2};
  EXPECT_EQ(0, IconIndexFile::Distance(directory_entry, 96, 1));
}

// This test verifies a correct retun of distance.
TEST_F(IconIndexFileTest, NonZeroDistance) {
  IconIndexFile::DirectoryEntry directory_entry = {.size = 48, .scale = 2};
  EXPECT_EQ(100, IconIndexFile::Distance(directory_entry, 48, 1));
}

// This test verifies that PerfectMatch returns true when size and scale matches
// respectively.
TEST_F(IconIndexFileTest, PerfectMatch) {
  IconIndexFile::DirectoryEntry directory_entry = {.size = 48, .scale = 2};
  EXPECT_TRUE(IconIndexFile::PerfectMatch(directory_entry, 48, 2));
}

// This test verifies that PerfectMatch returns false when they don't.
TEST_F(IconIndexFileTest, NotPerfectMatch) {
  IconIndexFile::DirectoryEntry directory_entry = {.size = 48, .scale = 2};
  EXPECT_FALSE(IconIndexFile::PerfectMatch(directory_entry, 96, 1));
}

// This test verifies a threshold type within limit case works correctly.
TEST_F(IconIndexFileTest, ThresholdWithinLimit) {
  IconIndexFile::DirectoryEntry directory_entry = {
      .size = 48, .scale = 2, .type = "Threshold"};
  EXPECT_TRUE(IconIndexFile::WithinLimit(directory_entry, 96 * 1));
}

// This test verifies a threshold type not with limit case works correctly.
TEST_F(IconIndexFileTest, ThresholdNotWithinLimit) {
  IconIndexFile::DirectoryEntry directory_entry = {
      .size = 48, .scale = 2, .type = "Threshold"};
  EXPECT_FALSE(IconIndexFile::WithinLimit(directory_entry, 97 * 1));
}

// This test verifies a scalable type within limit case works correctly.
TEST_F(IconIndexFileTest, ScalableWithinLimit) {
  IconIndexFile::DirectoryEntry directory_entry = {
      .type = "Scalable", .max_size = 96, .min_size = 48};
  EXPECT_TRUE(IconIndexFile::WithinLimit(directory_entry, 64 * 1));
}

// This test verifies a scalable type not with limit case works correctly.
TEST_F(IconIndexFileTest, ScalableNotWithinLimit) {
  IconIndexFile::DirectoryEntry directory_entry = {
      .type = "Scalable", .max_size = 96, .min_size = 48};
  EXPECT_FALSE(IconIndexFile::WithinLimit(directory_entry, 97 * 1));
}

// This test verifies a fixed type within limit case works correctly.
TEST_F(IconIndexFileTest, FixedWithinLimit) {
  IconIndexFile::DirectoryEntry directory_entry = {.size = 48, .type = "Fixed"};
  EXPECT_TRUE(IconIndexFile::WithinLimit(directory_entry, 48 * 1));
}

// This test verifies a fixed type not with limit case works correctly.
TEST_F(IconIndexFileTest, FixedNotWithinLimit) {
  IconIndexFile::DirectoryEntry directory_entry = {.size = 48, .type = "Fixed"};
  EXPECT_FALSE(IconIndexFile::WithinLimit(directory_entry, 48 * 2));
}

}  // namespace garcon
}  // namespace vm_tools
