// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/files/file_util.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iterator>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/syslog_logging.h>

namespace brillo {

namespace {

enum class FSObjectType {
  RegularFile = 0,
  Directory,
};

SafeFD::SafeFDResult OpenOrRemake(SafeFD* parent,
                                  const std::string& name,
                                  FSObjectType type,
                                  int permissions,
                                  uid_t uid,
                                  gid_t gid,
                                  int flags) {
  SafeFD::Error err = IsValidFilename(name);
  if (SafeFD::IsError(err)) {
    return std::make_pair(SafeFD(), err);
  }

  SafeFD::SafeFDResult (SafeFD::*maker)(const base::FilePath&, mode_t, uid_t,
                                        gid_t, int);
  if (type == FSObjectType::Directory) {
    maker = &SafeFD::MakeDir;
  } else {
    maker = &SafeFD::MakeFile;
  }

  SafeFD child;
  std::tie(child, err) =
      (parent->*maker)(base::FilePath(name), permissions, uid, gid, flags);
  if (child.is_valid()) {
    return std::make_pair(std::move(child), err);
  }

  // Rmdir should be used on directories. However, kWrongType indicates when
  // a directory was expected and a non-directory was found or when a
  // directory was found but not expected, so XOR was used.
  if ((type == FSObjectType::Directory) ^ (err == SafeFD::Error::kWrongType)) {
    err = parent->Rmdir(name, true /*recursive*/);
  } else {
    err = parent->Unlink(name);
  }
  if (SafeFD::IsError(err)) {
    PLOG(ERROR) << "Failed to clean up \"" << name << "\"";
    return std::make_pair(SafeFD(), err);
  }

  std::tie(child, err) =
      (parent->*maker)(base::FilePath(name), permissions, uid, gid, flags);
  return std::make_pair(std::move(child), err);
}

bool AllAreSeparators(const std::string& input) {
  for (auto it : input) {
    if (!base::FilePath::IsSeparator(it))
      return false;
  }

  return true;
}

base::FilePath MakeAbsolute(const base::FilePath& path) {
  // realpath isn't used here because it resolves symlinks.
  if (path.IsAbsolute()) {
    return path;
  }

  // The root path is used as a fallback in the case GetCurrentDirectory fails
  // which in theory should never happen.
  base::FilePath working_dir("/");
  base::GetCurrentDirectory(&working_dir);
  return working_dir.Append(path);
}

bool DeleteInternal(const base::FilePath& path, bool deep) {
  const auto abs_path = SimplifyPath(MakeAbsolute(path));

  // Delete operations using SafeFD are applied to the parent directory.
  const auto parent = abs_path.DirName();
  // Handle the case path doesn't have a parent and the CWD is returned.
  if (!parent.IsParent(abs_path)) {
    return false;
  }
  SafeFD fd;
  SafeFD::Error err;
  std::tie(fd, err) = SafeFD::Root().first.OpenExistingDir(parent);
  if (!fd.is_valid()) {
    if (err == SafeFD::Error::kDoesNotExist) {
      return true;
    }
    LOG(ERROR) << "Failed to open " << parent;
    return false;
  }

  return DeletePath(&fd, abs_path.BaseName().value(), deep);
}

}  // namespace

base::FilePath SimplifyPath(const base::FilePath& path) {
  std::vector<std::string> components;
  if (path.empty()) {
    return path;
  }

  base::FilePath current;
  base::FilePath base;

  size_t reserve = 0;
  size_t parent_dir = 0;
  // Capture path components.
  for (current = path; current != current.DirName();
       current = current.DirName()) {
    base = current.BaseName();

    // Skip path separators and "."
    if (AllAreSeparators(base.value()) ||
        base.value() == base::FilePath::kCurrentDirectory) {
      continue;
    }

    // Count parent directory operators.
    if (base.value() == base::FilePath::kParentDirectory) {
      ++parent_dir;
      continue;
    }

    // Skip path components negated by parent directory operators.
    if (parent_dir > 0) {
      --parent_dir;
      continue;
    }

    components.push_back(base.value());
    reserve += components.back().size();
  }

  // Handle relative paths
  base = current.BaseName();
  if (base.value() == base::FilePath::kCurrentDirectory ||
      base.value().empty()) {
    for (size_t x = 0; x < parent_dir; ++x) {
      components.push_back(base::FilePath::kParentDirectory);
      reserve += components.back().size();
    }
    // Handle absolute paths
  } else if (base.value() == "/") {
    if (components.empty()) {
      return base::FilePath("/");
    }
    // Use an empty string since the path separator will still be added.
    components.push_back("");
    reserve += components.back().size();
    // This shouldn't happen unless the code is being used on Windows.
  } else {
    CHECK(false) << "Got unexpected path base";
  }

  // Count separators
  reserve += components.size() - 1;
  // JoinString isn't used because it doesn't accept reverse iterators.
  std::string result;
  result.reserve(reserve);

  auto riter = components.rbegin();
  DCHECK(riter != components.rend());

  result.append(riter->data(), riter->size());
  ++riter;

  for (; riter != components.rend(); ++riter) {
    result.append("/", 1);
    result.append(riter->data(), riter->size());
  }

  // Check that we pre-allocated correctly.
  DCHECK_EQ(reserve, result.size());

  return base::FilePath(result);
}

SafeFD::Error IsValidFilename(const std::string& filename) {
  if (filename == "." || filename == ".." ||
      filename.find("/") != std::string::npos) {
    return SafeFD::Error::kBadArgument;
  }
  return SafeFD::Error::kNoError;
}

base::FilePath GetFDPath(int fd) {
  const base::FilePath proc_fd(base::StringPrintf("/proc/self/fd/%d", fd));
  base::FilePath resolved;
  if (!base::ReadSymbolicLink(proc_fd, &resolved)) {
    LOG(ERROR) << "Failed to read " << proc_fd.value();
    return base::FilePath();
  }
  return resolved;
}

SafeFD::SafeFDResult OpenOrRemakeDir(SafeFD* parent,
                                     const std::string& name,
                                     int permissions,
                                     uid_t uid,
                                     gid_t gid,
                                     int flags) {
  return OpenOrRemake(parent, name, FSObjectType::Directory, permissions, uid,
                      gid, flags);
}

SafeFD::SafeFDResult OpenOrRemakeFile(SafeFD* parent,
                                      const std::string& name,
                                      int permissions,
                                      uid_t uid,
                                      gid_t gid,
                                      int flags) {
  return OpenOrRemake(parent, name, FSObjectType::RegularFile, permissions, uid,
                      gid, flags);
}

bool DeletePath(SafeFD* parent, const std::string& name, bool deep) {
  // Assume it is a directory and if that fails, try as a file.
  SafeFD::Error err = parent->Rmdir(name, deep /* recursive */);
  if (!SafeFD::IsError(err) || err == SafeFD::Error::kDoesNotExist ||
      errno == ENOENT) {
    return true;
  }
  err = parent->Unlink(name);
  return !SafeFD::IsError(err);
}

bool DeleteFile(const base::FilePath& path) {
  return DeleteInternal(path, false /* deep */);
}

bool DeletePathRecursively(const base::FilePath& path) {
  return DeleteInternal(path, true /* deep */);
}

}  // namespace brillo
