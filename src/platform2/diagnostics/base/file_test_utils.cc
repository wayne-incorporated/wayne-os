// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/base/file_test_utils.h"

#include <memory>
#include <string>

#include <base/check.h>
#include <base/no_destructor.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/files/file_util.h>

namespace diagnostics {
namespace {

base::FilePath& RootDir() {
  static base::NoDestructor<base::FilePath> root_dir{};
  return *root_dir;
}

}  // namespace

base::FilePath GetRootDir() {
  if (RootDir().empty())
    return base::FilePath{"/"};
  return RootDir();
}

base::FilePath GetRootedPath(base::FilePath path) {
  CHECK(!path.empty());
  CHECK(path.IsAbsolute());
  const base::FilePath& root_dir = RootDir();
  // If the path is not overridden, don't modify the path.
  if (root_dir.empty())
    return path;

  CHECK(!root_dir.IsParent(path))
      << "The path is already under the test root " << root_dir;
  // Special case for who only want to get the root dir, which is not supported
  // by `AppendRelativePath()`.
  if (path == base::FilePath("/"))
    return root_dir;
  base::FilePath res = root_dir;
  CHECK(base::FilePath("/").AppendRelativePath(path, &res))
      << "Cannot append path " << path << " to " << root_dir
      << " related to /.";
  return res;
}

ScopedRootDirOverrides::ScopedRootDirOverrides() {
  CHECK(temp_dir_.CreateUniqueTempDir());
  CHECK(RootDir().empty()) << "Cannot set twice.";
  RootDir() = temp_dir_.GetPath();
}

ScopedRootDirOverrides::ScopedRootDirOverrides(base::FilePath root_dir) {
  CHECK(!root_dir.empty());
  CHECK(root_dir.IsAbsolute());
  CHECK(RootDir().empty()) << "Cannot set twice.";
  RootDir() = root_dir;
}

ScopedRootDirOverrides::~ScopedRootDirOverrides() {
  RootDir() = base::FilePath{};
}

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

void BaseFileTest::SetTestRoot(const base::FilePath& path) {
  // Reset old before create the new instance.
  scoped_root_dir_.reset();
  scoped_root_dir_ = std::make_unique<ScopedRootDirOverrides>(path);
}

void BaseFileTest::UnsetPath(const PathType& path) const {
  ASSERT_FALSE(GetRootDir().empty());
  ASSERT_TRUE(brillo::DeletePathRecursively(GetPathUnderRoot(path)));
}

void BaseFileTest::SetSymbolicLink(const PathType& target,
                                   const PathType& path) {
  UnsetPath(path);
  auto file = GetPathUnderRoot(path);
  ASSERT_TRUE(base::CreateDirectory(file.DirName()));
  auto real_target = target.file_path().IsAbsolute() ? GetPathUnderRoot(target)
                                                     : target.file_path();
  ASSERT_TRUE(base::CreateSymbolicLink(real_target, file));
}

base::FilePath BaseFileTest::GetPathUnderRoot(const PathType& path) const {
  if (!path.file_path().IsAbsolute())
    return GetRootedPath(base::FilePath{"/"}.Append(path.file_path()));
  return GetRootedPath(path.file_path());
}

const base::FilePath& BaseFileTest::root_dir() const {
  return RootDir();
}

}  // namespace diagnostics
