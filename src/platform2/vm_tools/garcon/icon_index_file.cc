// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <limits>
#include <memory>
#include <utility>

#include <base/environment.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

#include "vm_tools/garcon/icon_index_file.h"
#include "vm_tools/garcon/ini_parse_util.h"

namespace {
// Ridiculously large size for an icon index file.
constexpr size_t kMaxIconIndexFileSize = 10485760;  // 10 MB
// Name for the icon theme section we want.
constexpr char kIconThemeSectionName[] = "Icon Theme";
constexpr char kIconThemeName[] = "Name";
constexpr char kIconThemeNameWithLocale[] = "Name[";
constexpr char kIconThemeDirectories[] = "Directories";
constexpr char kIconThemeScaledDirectories[] = "ScaledDirectories";
constexpr char kDirectorySize[] = "Size";
constexpr char kDirectoryScale[] = "Scale";
constexpr char kDirectoryContext[] = "Context";
constexpr char kDirectoryType[] = "Type";
constexpr char kDirectoryMaxSize[] = "MaxSize";
constexpr char kDirectoryMinSize[] = "MinSize";
constexpr char kDirectoryThreshold[] = "Threshold";
// Icon directory types.
constexpr char kDirectoryTypeThreshold[] = "Threshold";
constexpr char kDirectoryTypeScalable[] = "Scalable";
// Valid types of directory entries in index files.
const char* const kValidDirectoryContexts[] = {"Applications", "MimeTypes"};
const char* const kValidDirectorySuffixes[] = {"apps", "mimetypes"};

// Max value for any integer in the file. Nothing should be large values outside
// of any reasonable pixel size/scale/threshold, nor should they be
// non-positive. This would be higher but we want to ensure squaring this number
// and multiplying by 100 doesn't violate the 32-bit max.
constexpr size_t kMaxReasonableValue = 4096;  // 4K
bool IsValueReasonable(int x) {
  return x > 0 && x < kMaxReasonableValue;
}

}  // namespace

namespace vm_tools {
namespace garcon {

// static
int IconIndexFile::Distance(const DirectoryEntry& directory_entry,
                            int search_size,
                            int search_scale) {
  int directory_scaled_size = directory_entry.size * directory_entry.scale;
  int search_scaled_size = search_size * search_scale;
  if (directory_scaled_size >= search_scaled_size) {
    return (directory_scaled_size - search_scaled_size) * 100 /
           search_scaled_size;
  } else {
    return (search_scaled_size - directory_scaled_size) * 100 /
           directory_scaled_size;
  }
}

// static
bool IconIndexFile::PerfectMatch(const DirectoryEntry& directory_entry,
                                 int search_size,
                                 int search_scale) {
  return directory_entry.size == search_size &&
         directory_entry.scale == search_scale;
}

// static
bool IconIndexFile::WithinLimit(const DirectoryEntry& directory_entry,
                                int search_size) {
  if (directory_entry.type == kDirectoryTypeThreshold) {
    if (search_size >= directory_entry.size) {
      return directory_entry.size * directory_entry.threshold >= search_size;
    } else {
      return search_size * directory_entry.threshold >= directory_entry.size;
    }
  } else if (directory_entry.type == kDirectoryTypeScalable) {
    return search_size >= directory_entry.min_size &&
           search_size <= directory_entry.max_size;
  } else {
    return search_size == directory_entry.size;
  }
}

// static
std::unique_ptr<IconIndexFile> IconIndexFile::ParseIconIndexFile(
    const base::FilePath& icon_dir) {
  std::unique_ptr<IconIndexFile> retval(new IconIndexFile(icon_dir));
  if (!retval->LoadFromFile(icon_dir.Append("index.theme"))) {
    retval.reset();
  }
  return retval;
}

std::vector<base::FilePath> IconIndexFile::GetPathsForSizeAndScale(
    int icon_size, int scale) {
  std::vector<base::FilePath> retval;
  std::multimap<int, const DirectoryEntry*> path_map;
  std::vector<base::FilePath> within_limit;
  std::vector<base::FilePath> the_rest;
  for (const auto& directory_entry : directory_entries_) {
    path_map.emplace(Distance(directory_entry, icon_size, scale),
                     &directory_entry);
  }
  for (const auto& path_element : path_map) {
    if (PerfectMatch(*path_element.second, icon_size, scale)) {
      retval.emplace_back(icon_dir_.Append(path_element.second->directory));
    } else if (WithinLimit(*path_element.second, icon_size * scale)) {
      within_limit.emplace_back(
          icon_dir_.Append(path_element.second->directory));
    } else {
      the_rest.emplace_back(icon_dir_.Append(path_element.second->directory));
    }
  }
  retval.insert(retval.end(), std::make_move_iterator(within_limit.begin()),
                std::make_move_iterator(within_limit.end()));
  retval.insert(retval.end(), std::make_move_iterator(the_rest.begin()),
                std::make_move_iterator(the_rest.end()));
  return retval;
}

bool IconIndexFile::CloseIconThemeSection(
    std::unique_ptr<IconThemeEntry> icon_theme_entry) {
  for (std::string& directory : icon_theme_entry->directories) {
    directories_.emplace(std::move(directory));
  }
  for (std::string& directory : icon_theme_entry->scaled_directories) {
    scaled_directories_.emplace(std::move(directory));
  }
  return true;
}

void IconIndexFile::FillInDefaultValues(DirectoryEntry* directory_entry) {
  if (directory_entry->type.empty()) {
    directory_entry->type = kDirectoryTypeThreshold;
  }
  if (directory_entry->max_size == 0) {
    directory_entry->max_size = directory_entry->size;
  }
  if (directory_entry->min_size == 0) {
    directory_entry->min_size = directory_entry->size;
  }
}

bool IconIndexFile::CloseDirectorySection(
    std::unique_ptr<DirectoryEntry> directory_entry) {
  const base::FilePath& directory = directory_entry->directory;
  if (directories_.find(directory) == directories_.end() &&
      scaled_directories_.find(directory) == scaled_directories_.end()) {
    LOG(ERROR) << "Failed parsing icon index file due to directory section"
                  " name "
               << directory
               << " not appearing in icon theme section directories";
    return false;
  }

  // Make sure the values in this directory section are reasonable.
  if (directory_entry->directory.IsAbsolute() ||
      !IsValueReasonable(directory_entry->scale) ||
      !IsValueReasonable(directory_entry->size) ||
      !IsValueReasonable(directory_entry->threshold)) {
    // Don't fail parsing the whole file, just don't add this directory.
    LOG(ERROR) << "Ignoring directory section \"" << directory
               << "\" in icon index file due to invalid path, or unreasonable "
                  "value for scale, size, or threshold";
    return true;
  }

  bool valid_dir = false;
  for (const char* dir_context : kValidDirectoryContexts) {
    if (directory_entry->context == dir_context) {
      valid_dir = true;
      break;
    }
  }
  if (!valid_dir) {
    for (const char* dir_suffix : kValidDirectorySuffixes) {
      if (base::EndsWith(directory.value(), dir_suffix,
                         base::CompareCase::SENSITIVE)) {
        valid_dir = true;
        break;
      }
    }
  }
  if (valid_dir) {
    FillInDefaultValues(directory_entry.get());
    directory_entries_.emplace_back(std::move(*directory_entry));
  }
  return true;
}

bool IconIndexFile::LoadFromFile(const base::FilePath& file_path) {
  // Fail fast if the file doesn't exist, which can happen due to the number
  // of directories we are searching.
  if (!base::PathExists(file_path))
    return false;

  std::unique_ptr<IconThemeEntry> icon_theme_entry =
      std::make_unique<IconThemeEntry>();
  std::unique_ptr<DirectoryEntry> directory_entry =
      std::make_unique<DirectoryEntry>();

  enum ParsingPhase { start, icon_theme_section, directory_section };
  ParsingPhase parsing_phase = start;

  // First read in the file as a string.
  std::string icon_index_contents;
  if (!ReadFileToStringWithMaxSize(file_path, &icon_index_contents,
                                   kMaxIconIndexFileSize)) {
    LOG(ERROR) << "Failed reading icon index file: " << file_path.value();
    return false;
  }

  std::vector<base::StringPiece> icon_index_lines =
      base::SplitStringPiece(icon_index_contents, "\n", base::TRIM_WHITESPACE,
                             base::SPLIT_WANT_NONEMPTY);

  // Go through the file line by line.
  for (const auto& curr_line : icon_index_lines) {
    if (curr_line.front() == '#') {
      // Skip comment lines.
      continue;
    }
    if (curr_line.front() == '[') {
      // Section name.
      base::StringPiece section_name = ParseGroupName(curr_line);
      if (section_name.empty()) {
        continue;
      }
      if (parsing_phase == start) {
        if (section_name == kIconThemeSectionName) {
          parsing_phase = icon_theme_section;
        }
      } else if (parsing_phase == icon_theme_section) {
        if (!CloseIconThemeSection(std::move(icon_theme_entry))) {
          return false;
        }
        parsing_phase = directory_section;
        directory_entry->directory = base::FilePath(section_name);
      } else if (parsing_phase == directory_section) {
        if (!CloseDirectorySection(std::move(directory_entry))) {
          return false;
        }
        directory_entry = std::make_unique<DirectoryEntry>();
        directory_entry->directory = base::FilePath(section_name);
      }
    } else if (parsing_phase == start) {
      // We are before the icon theme section and this line doesn't begin that
      // entry so skip it.
      continue;
    } else {
      // Parse the key/value pair on this line.
      std::pair<std::string, std::string> key_value =
          ExtractKeyValuePair(curr_line);
      if (key_value.second.empty()) {
        // Invalid key/value pair since there was no delimiter, skip ths line.
        continue;
      }
      // Check for matching names against all the keys. For the ones that can
      // have a locale in the key name, do those last since we do a startsWith
      // comparison on those.
      std::string key = key_value.first;
      if (parsing_phase == icon_theme_section) {
        if (key == kIconThemeName) {
          icon_theme_entry->locale_name_map[""] =
              UnescapeString(key_value.second);
        } else if (key == kIconThemeDirectories) {
          ParseMultiString(key_value.second, &icon_theme_entry->directories,
                           ',');
        } else if (key == kIconThemeScaledDirectories) {
          ParseMultiString(key_value.second,
                           &icon_theme_entry->scaled_directories, ',');
        } else if (base::StartsWith(key, kIconThemeNameWithLocale,
                                    base::CompareCase::SENSITIVE)) {
          std::string locale = ExtractKeyLocale(key);
          if (locale.empty()) {
            continue;
          }
          icon_theme_entry->locale_name_map[locale] =
              UnescapeString(key_value.second);
        }
      } else if (parsing_phase == directory_section) {
        if (key == kDirectorySize) {
          base::StringToInt(key_value.second, &directory_entry->size);
        } else if (key == kDirectoryScale) {
          base::StringToInt(key_value.second, &directory_entry->scale);
        } else if (key == kDirectoryContext) {
          directory_entry->context = UnescapeString(key_value.second);
        } else if (key == kDirectoryType) {
          directory_entry->type = UnescapeString(key_value.second);
        } else if (key == kDirectoryMaxSize) {
          base::StringToInt(key_value.second, &directory_entry->max_size);
        } else if (key == kDirectoryMinSize) {
          base::StringToInt(key_value.second, &directory_entry->min_size);
        } else if (key == kDirectoryThreshold) {
          base::StringToInt(key_value.second, &directory_entry->threshold);
        }
      }
    }
  }

  if (parsing_phase != directory_section) {
    LOG(ERROR) << "Failed reading icon index file: " << file_path.value();
    return false;
  }
  if (!CloseDirectorySection(std::move(directory_entry))) {
    return false;
  }
  return true;
}

}  // namespace garcon
}  // namespace vm_tools
