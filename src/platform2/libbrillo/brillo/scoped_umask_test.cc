// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/scoped_umask.h"

#include <fcntl.h>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace brillo {
namespace {

constexpr int kPermissions600 =
    base::FILE_PERMISSION_READ_BY_USER | base::FILE_PERMISSION_WRITE_BY_USER;
constexpr int kPermissions700 = base::FILE_PERMISSION_USER_MASK;
constexpr mode_t kMask700 = ~(0700);
constexpr mode_t kMask600 = ~(0600);

void CheckFilePermissions(const base::FilePath& path,
                          int expected_permissions) {
  int mode = 0;
  // Try to create a file with broader permissions than the mask may provide.
  base::ScopedFD fd(
      HANDLE_EINTR(open(path.value().c_str(), O_WRONLY | O_CREAT, 0777)));
  EXPECT_TRUE(fd.is_valid());
  EXPECT_TRUE(base::GetPosixFilePermissions(path, &mode));
  EXPECT_EQ(mode, expected_permissions);
}

}  // namespace

TEST(ScopedUmask, CheckUmaskScope) {
  base::ScopedTempDir tmpdir;
  CHECK(tmpdir.CreateUniqueTempDir());

  brillo::ScopedUmask outer_scoped_umask_(kMask700);
  CheckFilePermissions(tmpdir.GetPath().AppendASCII("file1.txt"),
                       kPermissions700);
  {
    // A new scoped umask should result in different permissions for files
    // created in this scope.
    brillo::ScopedUmask inner_scoped_umask_(kMask600);
    CheckFilePermissions(tmpdir.GetPath().AppendASCII("file2.txt"),
                         kPermissions600);
  }
  // Since inner_scoped_umask_ has been deconstructed, permissions on all new
  // files should now use outer_scoped_umask_.
  CheckFilePermissions(tmpdir.GetPath().AppendASCII("file3.txt"),
                       kPermissions700);
}

}  // namespace brillo
