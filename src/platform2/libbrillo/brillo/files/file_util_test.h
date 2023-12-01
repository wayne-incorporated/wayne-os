// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Filesystem-related utility functions.

#ifndef LIBBRILLO_BRILLO_FILES_FILE_UTIL_TEST_H_
#define LIBBRILLO_BRILLO_FILES_FILE_UTIL_TEST_H_

#include <string>
#include <vector>

#include <base/files/scoped_temp_dir.h>
#include <brillo/files/safe_fd.h>
#include <gtest/gtest.h>

namespace brillo {

// Convert the SafeFD::Error enum class to a string for readability of
// test results.
std::string to_string(brillo::SafeFD::Error err);

// Helper to enable gtest to print SafeFD::Error results in a way that is easier
// to read.
std::ostream& operator<<(std::ostream& os, const brillo::SafeFD::Error err);

// Gets a short random string that can be used as part of a file name.
std::string GetRandomSuffix();

class FileTest : public testing::Test {
 public:
  static constexpr char kFileName[] = "test.temp";
  static constexpr char kSubdirName[] = "test_dir";
  static constexpr char kSymbolicFileName[] = "sym_test.temp";
  static constexpr char kSymbolicDirName[] = "sym_dir";

  static void SetUpTestCase();

  FileTest();
  ~FileTest();

 protected:
  std::vector<char> temp_dir_path_;
  base::FilePath file_path_;
  base::FilePath sub_dir_path_;
  base::FilePath symlink_file_path_;
  base::FilePath symlink_dir_path_;
  base::ScopedTempDir temp_dir_;
  SafeFD root_;

  [[nodiscard]] bool SetupSubdir();

  [[nodiscard]] bool SetupSymlinks();

  // Writes |contents| to |file_path_|. Pulled into a separate function just
  // to improve readability of tests.
  [[nodiscard]] bool WriteFile(const std::string& contents);

  // Verifies that the file at |file_path_| exists and contains |contents|.
  void ExpectFileContains(const std::string& contents);

  // Verifies that the file at |file_path_| has |permissions|.
  void ExpectPermissions(base::FilePath path, int permissions);

  // Creates a file with a random name in the temporary directory.
  [[nodiscard]] base::FilePath GetTempName();
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_FILES_FILE_UTIL_TEST_H_
