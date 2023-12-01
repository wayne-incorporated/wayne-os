// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/samba_interface_impl.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace smbfs {
namespace {

constexpr char kUsername[] = "my-username";

class TestSambaInterfaceImpl : public SambaInterfaceImpl {
 public:
  TestSambaInterfaceImpl() : SambaInterfaceImpl() {}
};

}  // namespace

class SambaInterfaceImplTest : public testing::Test {};

TEST_F(SambaInterfaceImplTest, MakeStatModeBitsFromDOSAttributes) {
  TestSambaInterfaceImpl samba_impl;

  // Check: The directory attribute sets the directory type bit.
  uint16_t dos_attrs = SMBC_DOS_MODE_DIRECTORY;
  mode_t out_mode = samba_impl.MakeStatModeBitsFromDOSAttributes(dos_attrs);
  EXPECT_TRUE(out_mode & S_IFDIR);
  EXPECT_FALSE(out_mode & S_IFREG);

  // Check: Absence of the directory attribute sets the file type bit.
  dos_attrs = 0;
  out_mode = samba_impl.MakeStatModeBitsFromDOSAttributes(dos_attrs);
  EXPECT_TRUE(out_mode & S_IFREG);
  EXPECT_FALSE(out_mode & S_IFDIR);

  // Check: Special attributes (without the directory attribute) set the file
  // type bit.
  dos_attrs = SMBC_DOS_MODE_ARCHIVE;
  out_mode = samba_impl.MakeStatModeBitsFromDOSAttributes(dos_attrs);
  EXPECT_TRUE(out_mode & S_IFREG);

  dos_attrs = SMBC_DOS_MODE_SYSTEM;
  out_mode = samba_impl.MakeStatModeBitsFromDOSAttributes(dos_attrs);
  EXPECT_TRUE(out_mode & S_IFREG);

  dos_attrs = SMBC_DOS_MODE_HIDDEN;
  out_mode = samba_impl.MakeStatModeBitsFromDOSAttributes(dos_attrs);
  EXPECT_TRUE(out_mode & S_IFREG);

  // Check: Absence of the read-only attribute sets the user write bit.
  dos_attrs = 0;
  out_mode = samba_impl.MakeStatModeBitsFromDOSAttributes(dos_attrs);
  EXPECT_TRUE(out_mode & S_IWUSR);

  // Check: Presence of the read-only attribute clears the user write bit.
  dos_attrs = SMBC_DOS_MODE_READONLY;
  out_mode = samba_impl.MakeStatModeBitsFromDOSAttributes(dos_attrs);
  EXPECT_FALSE(out_mode & S_IWUSR);

  dos_attrs = SMBC_DOS_MODE_READONLY | SMBC_DOS_MODE_DIRECTORY;
  out_mode = samba_impl.MakeStatModeBitsFromDOSAttributes(dos_attrs);
  EXPECT_TRUE(out_mode & (S_IFDIR | S_IWUSR));
}

TEST_F(SambaInterfaceImplTest, UpdateCredentials) {
  TestSambaInterfaceImpl samba_impl;

  EXPECT_FALSE(samba_impl.credentials_);
  samba_impl.UpdateCredentials(
      std::make_unique<SmbCredential>("" /* workgroup */, kUsername, nullptr));

  EXPECT_TRUE(samba_impl.credentials_);
  EXPECT_EQ(samba_impl.credentials_->username, kUsername);
}

}  // namespace smbfs
