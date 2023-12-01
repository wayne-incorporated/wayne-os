// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/cache_cleaner.h"

#include <fnmatch.h>

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <base/values.h>
#include <brillo/files/file_util.h>

#include "arc/apk-cache/apk_cache_utils.h"
#include "arc/apk-cache/cache_cleaner_db.h"
#include "arc/apk-cache/cache_cleaner_utils.h"

namespace apk_cache {

constexpr char kAttrJson[] = "attr.json";
constexpr char kApkExtension[] = ".apk";
constexpr char kObbExtension[] = ".obb";
constexpr char kMainObbPrefix[] = "main.";
constexpr char kPatchObbPrefix[] = "patch.";

namespace {

constexpr char kKeyAttributesAtime[] = "attributes.atime";

// Removes all the files (if any) from cache root. Does not remove
// directories. Returns true if all the intended files were deleted.
bool RemoveUnexpectedFilesFromCacheRoot(const base::FilePath& cache_root) {
  std::unordered_set<std::string> database_files(
      kDatabaseFiles, kDatabaseFiles + kDatabaseFilesCount);
  return RemoveUnexpectedItemsFromDir(
      cache_root,
      base::FileEnumerator::FileType::FILES |
          base::FileEnumerator::FileType::SHOW_SYM_LINKS,
      database_files);
}

// Returns if |file_name| matches the |pattern|.
bool IsMatch(const std::string& file_name, const std::string& pattern) {
  return fnmatch(pattern.c_str(), file_name.c_str(), FNM_NOESCAPE) == 0;
}

// Parses contents of the attributes JSON file and verifies that last access
// time of the package was at most 30 days ago.
bool IsAccessTimeValid(const base::StringPiece& json_message) {
  auto root = base::JSONReader::ReadAndReturnValueWithError(
      json_message, base::JSON_PARSE_RFC);
  if (!root.has_value()) {
    LOG(ERROR) << "Reading attributes JSON failed (error message: "
               << root.error().message << ").";
    return false;
  }

  if (!root->is_dict()) {
    LOG(ERROR) << "Could not interpret the JSON as a dictionary.";
    return false;
  }

  const std::string* atime_str =
      root->GetDict().FindStringByDottedPath(kKeyAttributesAtime);
  if (!atime_str) {
    LOG(ERROR) << "Could not read the value of the access time with the "
               << kKeyAttributesAtime << " key.";
    return false;
  }

  base::Time atime;
  if (!base::Time::FromString(atime_str->c_str(), &atime)) {
    LOG(ERROR) << "Can not parse the date: " << *atime_str;
    return false;
  }

  const base::TimeDelta age = base::Time::Now() - atime;
  return age < kValidityPeriod;
}

// Verifies that package directory contains all the necessary files, does
// not contain any extra files/directories and was accessed within last 30 days.
// Returns true if the package is valid and should be kept in the cache.
bool IsPackageValid(const base::FilePath& package_path) {
  // Package directory must contain:
  // 1. One .apk file
  // 2. One attr.json file
  // 3. No or one main .obb file.
  // 4. No or one patch .obb file.
  // 5. No other files or directories.
  base::FileEnumerator files(package_path, false /* recursive */,
                             base::FileEnumerator::DIRECTORIES |
                                 base::FileEnumerator::FILES |
                                 base::FileEnumerator::SHOW_SYM_LINKS);
  int apk_count = 0;
  int attr_count = 0;
  int main_obb_count = 0;
  int patch_obb_count = 0;

  const std::string package_name = package_path.BaseName().value();
  const std::string apk_file_name = package_name + kApkExtension;
  const std::string main_obb_file_name =
      std::string(kMainObbPrefix) + "*" + package_name + kObbExtension;
  const std::string patch_obb_file_name =
      std::string(kPatchObbPrefix) + "*" + package_name + kObbExtension;

  for (base::FilePath file_path = files.Next(); !file_path.empty();
       file_path = files.Next()) {
    if (base::DirectoryExists(file_path)) {
      LOG(INFO) << "There are directories in " << package_path.value();
      return false;
    }

    const std::string file_name = file_path.BaseName().value();
    if (IsMatch(file_name, apk_file_name)) {
      apk_count++;
    } else if (IsMatch(file_name, kAttrJson)) {
      attr_count++;
    } else if (IsMatch(file_name, main_obb_file_name)) {
      main_obb_count++;
    } else if (IsMatch(file_name, patch_obb_file_name)) {
      patch_obb_count++;
    } else {
      LOG(INFO) << package_name << " contains unnecessary files.";
      return false;
    }
  }

  if (apk_count != 1) {
    LOG(INFO) << "Number of APK files is not equal to 1 in " << package_name;
    return false;
  }

  if (attr_count != 1) {
    LOG(INFO) << "Number of JSON attributes files is " << attr_count
              << " which not equal to 1 in " << package_name;
    return false;
  }

  if (main_obb_count > 1) {
    LOG(INFO) << "Number of patch OBB files is " << main_obb_count
              << ", which greater then 1 in " << package_name;
    return false;
  }

  if (patch_obb_count > 1) {
    LOG(INFO) << "Number of patch OBB files is " << patch_obb_count
              << ", which greater then 1 in " << package_name;
    return false;
  }

  const base::FilePath attr_file_path = package_path.Append(kAttrJson);
  std::string attr_json_contents;
  if (!base::ReadFileToString(attr_file_path, &attr_json_contents)) {
    LOG(ERROR) << "Could not read the attributes file.";
    return false;
  }

  return IsAccessTimeValid(attr_json_contents);
}

}  // namespace

bool Clean(const base::FilePath& cache_path) {
  if (!base::DirectoryExists(cache_path)) {
    LOG(ERROR) << "APK cache directory " << cache_path.value()
               << " does not exist";
    return false;
  }

  bool success = RemoveUnexpectedFilesFromCacheRoot(cache_path);

  base::FileEnumerator packages(
      cache_path, false /* recursive */,
      base::FileEnumerator::DIRECTORIES | base::FileEnumerator::SHOW_SYM_LINKS);

  for (base::FilePath package_path = packages.Next(); !package_path.empty();
       package_path = packages.Next()) {
    // Skip |files| directory which should be managed by database cleaner.
    if (package_path.BaseName().MaybeAsASCII() == std::string(kFilesBase))
      continue;

    if (!IsPackageValid(package_path)) {
      if (!brillo::DeletePathRecursively(package_path)) {
        LOG(ERROR) << "Error deletion path " << package_path.value();
        success = false;
      }
    } else {
      LOG(INFO) << "Package " << package_path.value() << " looks OK.";
    }
  }

  return success;
}

}  // namespace apk_cache
