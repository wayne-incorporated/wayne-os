// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/utils/file_test_utils.h"

#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/files/file_util.h>

namespace diagnostics {
namespace wilco {

bool WriteFileAndCreateParentDirs(const base::FilePath& file_path,
                                  const std::string& file_contents) {
  if (!base::CreateDirectory(file_path.DirName())) {
    return false;
  }
  return base::WriteFile(file_path, file_contents.c_str(),
                         file_contents.size()) == file_contents.size();
}

bool CreateCyclicSymbolicLink(const base::FilePath& file_path) {
  if (!base::CreateDirectory(file_path.DirName()))
    return false;
  return base::CreateSymbolicLink(file_path.DirName(),
                                  file_path.DirName().Append("foo"));
}

bool WriteFileAndCreateSymbolicLink(const base::FilePath& file_path,
                                    const std::string& file_contents,
                                    const base::FilePath& symlink_path) {
  if (!WriteFileAndCreateParentDirs(file_path, file_contents))
    return false;
  if (!base::CreateDirectory(symlink_path.DirName()))
    return false;
  return base::CreateSymbolicLink(file_path, symlink_path);
}

BaseFileTest::PathType::PathType(std::initializer_list<std::string> paths) {
  auto it = paths.begin();
  file_path_ = base::FilePath(*it);
  for (++it; it != paths.end(); ++it) {
    file_path_ = file_path_.Append(*it);
  }
}

void BaseFileTest::CreateTestRoot() {
  ASSERT_TRUE(root_dir_.empty());
  ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
  SetTestRoot(scoped_temp_dir_.GetPath());
  ASSERT_FALSE(root_dir_.empty());
}

void BaseFileTest::SetTestRoot(const base::FilePath& path) {
  ASSERT_TRUE(root_dir_.empty());
  ASSERT_FALSE(path.empty());
  root_dir_ = path;
}

void BaseFileTest::UnsetPath(const PathType& path) const {
  ASSERT_FALSE(root_dir_.empty());
  ASSERT_TRUE(brillo::DeletePathRecursively(GetPathUnderRoot(path)));
}

void BaseFileTest::SetSymbolicLink(const PathType& target,
                                   const PathType& path) {
  auto file = GetPathUnderRoot(path);
  ASSERT_TRUE(base::CreateDirectory(file.DirName()));
  auto real_target = target.file_path().IsAbsolute() ? GetPathUnderRoot(target)
                                                     : target.file_path();
  ASSERT_TRUE(base::CreateSymbolicLink(real_target, file));
}

base::FilePath BaseFileTest::GetPathUnderRoot(const PathType& path) const {
  CHECK(!root_dir_.empty());
  // Check if the path already under the test rootfs.
  CHECK(!root_dir_.IsParent(path.file_path()));
  if (!path.file_path().IsAbsolute())
    return root_dir_.Append(path.file_path());
  auto res = root_dir_;
  CHECK(base::FilePath("/").AppendRelativePath(path.file_path(), &res));
  return res;
}

const base::FilePath& BaseFileTest::root_dir() const {
  CHECK(!root_dir_.empty());
  return root_dir_;
}

}  // namespace wilco
}  // namespace diagnostics
