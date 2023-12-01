// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <string>
#include <vector>

#include <base/check.h>
#include <base/environment.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/format_macros.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "vm_tools/syslog/rotator.h"

namespace vm_tools {
namespace syslog {

class RotatorTest : public ::testing::Test {
 public:
  RotatorTest() {
    CHECK(scoped_temp_dir_.CreateUniqueTempDir());
    root_path_ = scoped_temp_dir_.GetPath();
  }

  void TearDown() override {}

  void GetFileNames(const std::string& pattern,
                    std::vector<std::string>* names) {
    std::vector<base::FileEnumerator::FileInfo> file_info;
    Rotator::GetSortedFileInfo(root_path_, pattern, &file_info);

    for (const auto& info : file_info) {
      names->push_back(info.GetName().BaseName().value());
    }
  }

  void WriteFileSequence(const std::string& base_name, int max_index) {
    for (int i = 0; i < max_index; ++i) {
      base::FilePath file_path = root_path_.Append(base_name);
      if (i > 0) {
        file_path = file_path.AddExtension(base::NumberToString(i));
      }
      int size = base::WriteFile(file_path, file_path.value().c_str(),
                                 file_path.value().size());
      VLOG(1) << "Wrote " << size << " bytes to " << file_path;
    }
  }

 protected:
  base::FilePath root_path_;

 private:
  base::ScopedTempDir scoped_temp_dir_;
};

TEST_F(RotatorTest, RotateEmptyDir) {
  EXPECT_TRUE(base::IsDirectoryEmpty(root_path_));
  Rotator rotator;
  rotator.RotateLogFiles(root_path_, 0);
  EXPECT_TRUE(base::IsDirectoryEmpty(root_path_));
}

TEST_F(RotatorTest, RotateNonLogDir) {
  EXPECT_TRUE(base::IsDirectoryEmpty(root_path_));
  WriteFileSequence("foo", 20);

  EXPECT_FALSE(base::IsDirectoryEmpty(root_path_));
  Rotator rotator;
  rotator.RotateLogFiles(root_path_, 10);
  EXPECT_FALSE(base::IsDirectoryEmpty(root_path_));

  std::vector<std::string> names;
  GetFileNames("foo*", &names);
  EXPECT_EQ(20, names.size());

  EXPECT_THAT(names, testing::ElementsAre(
                         "foo.19", "foo.18", "foo.17", "foo.16", "foo.15",
                         "foo.14", "foo.13", "foo.12", "foo.11", "foo.10",
                         "foo.9", "foo.8", "foo.7", "foo.6", "foo.5", "foo.4",
                         "foo.3", "foo.2", "foo.1", "foo"));
}

TEST_F(RotatorTest, RotateUnderfullDir) {
  EXPECT_TRUE(base::IsDirectoryEmpty(root_path_));

  WriteFileSequence("vm_foo.log", 5);
  EXPECT_FALSE(base::IsDirectoryEmpty(root_path_));
  Rotator rotator;
  rotator.RotateLogFiles(root_path_, 10);
  EXPECT_FALSE(base::IsDirectoryEmpty(root_path_));

  std::vector<std::string> names;
  GetFileNames("vm_foo.log*", &names);
  EXPECT_EQ(5, names.size());

  EXPECT_THAT(names, testing::ElementsAre("vm_foo.log.5", "vm_foo.log.4",
                                          "vm_foo.log.3", "vm_foo.log.2",
                                          "vm_foo.log.1"));
}

TEST_F(RotatorTest, RotateOverfullDir) {
  EXPECT_TRUE(base::IsDirectoryEmpty(root_path_));

  WriteFileSequence("vm_foo.log", 20);
  WriteFileSequence("crosvm.log", 6);
  Rotator rotator;
  rotator.RotateLogFiles(root_path_, 10);
  EXPECT_FALSE(base::IsDirectoryEmpty(root_path_));

  std::vector<std::string> vm_foo_names;
  GetFileNames("vm_foo.log*", &vm_foo_names);
  EXPECT_EQ(10, vm_foo_names.size());
  EXPECT_THAT(vm_foo_names, testing::ElementsAre(
                                "vm_foo.log.10", "vm_foo.log.9", "vm_foo.log.8",
                                "vm_foo.log.7", "vm_foo.log.6", "vm_foo.log.5",
                                "vm_foo.log.4", "vm_foo.log.3", "vm_foo.log.2",
                                "vm_foo.log.1"));

  std::vector<std::string> crosvm_names;
  GetFileNames("crosvm.log*", &crosvm_names);
  EXPECT_EQ(6, crosvm_names.size());
  EXPECT_THAT(
      crosvm_names,
      testing::ElementsAre("crosvm.log.6", "crosvm.log.5", "crosvm.log.4",
                           "crosvm.log.3", "crosvm.log.2", "crosvm.log.1"));
}

TEST_F(RotatorTest, RotateTimestampedNamedSequence) {
  EXPECT_TRUE(base::IsDirectoryEmpty(root_path_));

  int64_t ts0 = 12345670;

  for (int i = 0; i < 10; ++i) {
    base::FilePath file_path = root_path_.Append(
        base::StringPrintf("encoded-termina-%" PRId64 ".log", ts0 + i));
    if (i > 0) {
      file_path = file_path.AddExtension(base::NumberToString(i));
    }
    int size = base::WriteFile(file_path, file_path.value().c_str(),
                               file_path.value().size());
    VLOG(1) << "Wrote " << size << " bytes to " << file_path;
  }

  Rotator rotator;
  rotator.RotateLogFiles(root_path_, 6);
  EXPECT_FALSE(base::IsDirectoryEmpty(root_path_));

  std::vector<std::string> termina_names;
  GetFileNames("encoded-termina*.log*", &termina_names);
  EXPECT_EQ(6, termina_names.size());
  EXPECT_THAT(
      termina_names,
      testing::ElementsAre(
          "encoded-termina-12345675.log.6", "encoded-termina-12345674.log.5",
          "encoded-termina-12345673.log.4", "encoded-termina-12345672.log.3",
          "encoded-termina-12345671.log.2", "encoded-termina-12345670.log.1"));
}

}  // namespace syslog
}  // namespace vm_tools
