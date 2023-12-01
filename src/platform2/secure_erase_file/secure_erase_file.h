// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECURE_ERASE_FILE_SECURE_ERASE_FILE_H_
#define SECURE_ERASE_FILE_SECURE_ERASE_FILE_H_

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

namespace secure_erase_file {

// Returns true if the backing store for the file path supports secure erase.
//
// This can be used as a high-level check if we think the target file can be
// securely erased, but SecureErase() is not guaranteed to succeed.
BRILLO_EXPORT bool IsSupported(const base::FilePath& path);

// Securely erase a file, returning true on success and false on failure.
//
// Requires that:
//   - the file is a regular file.
//   - the file is stored on an eMMC device.
//   - the file is stored on a filesystem that supports FS_IOC_FIEMAP.
//   - the file does not span more than 32 extents.
//   - the underlying eMMC device and kernel support FITRIM.
//   - the underlying block point is not "anonymous", as with btrfs.
//
// This function internally calls IsSupported on the requested path, so it's not
// necessary to call IsSupported() before SecureErase().
//
// After unlink() and trim, this function reads from the file's original LBA
// range to ensure that it reads all 0s or 1s.
BRILLO_EXPORT bool SecureErase(const base::FilePath& path);

// Zeroouts the file, returning true on success and false on failure.
//
// Requires that:
//   - the file is a regular file.
//   - the file is stored on a filesystem that supports FS_IOC_FIEMAP.
//   - the file does not span more than 32 extents.
//   - the underlying block point is not "anonymous", as with btrfs.
//
// After unlink() and zeroout, this function reads from the file's original LBA
// range to ensure that it reads all 0s.
BRILLO_EXPORT bool ZeroFile(const base::FilePath& path);

// Drop all filesystem caches.
//
// This must be called after securely erasing files to ensure that cached data
// is not kept in the filesystem caches.
//
// This drops caches for all filesystems, and thus takes no path argument.
BRILLO_EXPORT bool DropCaches();

}  // namespace secure_erase_file

#endif  // SECURE_ERASE_FILE_SECURE_ERASE_FILE_H_
