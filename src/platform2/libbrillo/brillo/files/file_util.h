// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Filesystem-related utility functions.

#ifndef LIBBRILLO_BRILLO_FILES_FILE_UTIL_H_
#define LIBBRILLO_BRILLO_FILES_FILE_UTIL_H_

#include <unistd.h>

#include <string>

#include <brillo/files/safe_fd.h>

namespace brillo {

// Remove extra separators and any "." or ".." components.
// This does not access the filesystem. Relative paths may still have leading
// ".." components.
BRILLO_EXPORT base::FilePath SimplifyPath(const base::FilePath& path);

SafeFD::Error IsValidFilename(const std::string& filename);

// Obtain the canonical path of the file descriptor or base::FilePath() on
// failure.
BRILLO_EXPORT base::FilePath GetFDPath(int fd);

// Open or create a child directory named |name| as a child of |parent| with
// the specified permissions and ownership. Custom open flags can be set with
// |flags|. The directory will be re-created if:
// * The open operation fails (e.g. if |name| is not a directory).
// * The permissions do not match.
// * The ownership is different.
//
// Parameters
//  parent - An open SafeFD to the parent directory.
//  name - the name of the directory being created. It cannot have more than one
//    path component.
BRILLO_EXPORT SafeFD::SafeFDResult OpenOrRemakeDir(
    SafeFD* parent,
    const std::string& name,
    int permissions = SafeFD::kDefaultDirPermissions,
    uid_t uid = getuid(),
    gid_t gid = getgid(),
    int flags = O_RDONLY | O_CLOEXEC);

// Open or create a file named |name| under the directory |parent| with
// the specified permissions and ownership. Custom open flags can be set with
// |flags|. The file will be re-created if:
// * The open operation fails (e.g. |name| is a directory).
// * The permissions do not match.
// * The ownership is different.
//
// Parameters
//  parent - An open SafeFD to the parent directory.
//  name - the name of the file being created. It cannot have more than one
//    path component.
BRILLO_EXPORT SafeFD::SafeFDResult OpenOrRemakeFile(
    SafeFD* parent,
    const std::string& name,
    int permissions = SafeFD::kDefaultFilePermissions,
    uid_t uid = getuid(),
    gid_t gid = getgid(),
    int flags = O_RDWR | O_CLOEXEC);

// Deletes the given file or a directory. If |deep| is true this includes
// subdirectories and their contents, but if |deep| is false and the path is a
// non-empty directory, this will fail.
//
// Returns true if successful, false otherwise. It is considered successful
// to attempt to delete a path that does not exist.
BRILLO_EXPORT bool DeletePath(SafeFD* parent,
                              const std::string& name,
                              bool deep);

// Prefer DeletePath if using SafeFD to avoid ToCToU issues.
//
// This is meant to be a drop-in replacement for libchrome's DeleteFile,
// but with SafeFD used to avoid symlink issues.
//
// Deletes the given path, whether it's a file or a directory.
// If it's a directory, it will fail if the directory isn't empty.
//
// Returns true if successful, false otherwise. It is considered successful to
// attempt to delete a file that does not exist.
BRILLO_EXPORT bool DeleteFile(const base::FilePath& path);

// Prefer DeletePath if using SafeFD to avoid ToCToU issues.
//
// This is meant to be a drop-in replacement for libchrome's
// DeletePathRecursively, but with SafeFD used to avoid symlink issues.
//
// Deletes the given path, whether it's a file or a directory.
// If it's a directory, it's perfectly happy to delete all the
// directory's contents, including subdirectories and their contents.
//
// Returns true if successful, false otherwise. It is considered successful
// to attempt to delete a file that does not exist.
//
// if |path| is a symbolic link, this deletes only the symlink. (even if the
// symlink points to a non-existent file)
BRILLO_EXPORT bool DeletePathRecursively(const base::FilePath& path);

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_FILES_FILE_UTIL_H_
