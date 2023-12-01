// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_ICON_INDEX_FILE_H_
#define VM_TOOLS_GARCON_ICON_INDEX_FILE_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>

namespace vm_tools {
namespace garcon {
// Parses index.theme files according to the Icon Theme Specification here:
// https://specifications.freedesktop.org/icon-theme-spec/icon-theme-spec-latest.html
class IconIndexFile {
 public:
  // Returns empty unique_ptr if it fails to parse the index.theme file.
  static std::unique_ptr<IconIndexFile> ParseIconIndexFile(
      const base::FilePath& file_path);
  ~IconIndexFile() = default;

  // Returns a vector of FilePath that may contain an icon with the |icon_size|
  // and |scale| as preferred icons size and scale. Those two parameters are
  // preferences rather than strict criteria.
  std::vector<base::FilePath> GetPathsForSizeAndScale(int icon_size, int scale);

 private:
  struct IconThemeEntry {
    std::map<std::string, std::string> locale_name_map;
    std::vector<std::string> directories;
    std::vector<std::string> scaled_directories;
  };

  struct DirectoryEntry {
    base::FilePath directory;
    int size = 0;
    int scale = 1;
    std::string context;
    std::string type;
    int max_size = 0;
    int min_size = 0;
    // The threshold is interpreted as a multiplier. The spec is unclear.
    int threshold = 2;
  };

  explicit IconIndexFile(const base::FilePath& icon_dir)
      : icon_dir_(icon_dir) {}
  IconIndexFile(const IconIndexFile&) = delete;
  IconIndexFile& operator=(const IconIndexFile&) = delete;

  // Read and parse the input |file_path|.
  bool LoadFromFile(const base::FilePath& file_path);
  // Process the |icon_theme_entry| when the section is over.
  bool CloseIconThemeSection(std::unique_ptr<IconThemeEntry> icon_theme_entry);
  // Process the |directory_entry| when the section is over.
  bool CloseDirectorySection(std::unique_ptr<DirectoryEntry> directory_entry);
  // Assign certain default values to |directory_entry|. This is necessary since
  // some default value is a copy of other member variable value instead of
  // literal value.
  void FillInDefaultValues(DirectoryEntry* directory_entry);
  // Returns the percentage difference between the size of the desired icons and
  // the ones in the directory.
  static int Distance(const DirectoryEntry& directory_entry,
                      int search_size,
                      int search_scale);
  // Returns true if the size and scale of |directory_entry| is |search_size|
  // and |search_scale| respectively.
  static bool PerfectMatch(const DirectoryEntry& directory_entry,
                           int search_size,
                           int search_scale);
  // Returns true if the size parameters of |directory_entry| is within limit of
  // |search_size| by the spec definition.
  static bool WithinLimit(const DirectoryEntry& directory_entry,
                          int search_size);

  base::FilePath icon_dir_;

  std::vector<DirectoryEntry> directory_entries_;
  std::set<base::FilePath> directories_;
  std::set<base::FilePath> scaled_directories_;

  FRIEND_TEST(IconIndexFileTest, BasicZeroDistance);
  FRIEND_TEST(IconIndexFileTest, ScaledZeroDistance);
  FRIEND_TEST(IconIndexFileTest, NonZeroDistance);
  FRIEND_TEST(IconIndexFileTest, PerfectMatch);
  FRIEND_TEST(IconIndexFileTest, NotPerfectMatch);
  FRIEND_TEST(IconIndexFileTest, ThresholdWithinLimit);
  FRIEND_TEST(IconIndexFileTest, ThresholdNotWithinLimit);
  FRIEND_TEST(IconIndexFileTest, ScalableWithinLimit);
  FRIEND_TEST(IconIndexFileTest, ScalableNotWithinLimit);
  FRIEND_TEST(IconIndexFileTest, FixedWithinLimit);
  FRIEND_TEST(IconIndexFileTest, FixedNotWithinLimit);
};

}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_ICON_INDEX_FILE_H_
