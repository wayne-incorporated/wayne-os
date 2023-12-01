// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/util.h"

#include <fcntl.h>
#include <fuse_lowlevel.h>

#include <base/files/file_path.h>
#include <gtest/gtest.h>

namespace smbfs {
namespace {

TEST(UtilTest, OpenFlagsToString) {
  EXPECT_EQ("O_RDONLY", OpenFlagsToString(O_RDONLY));
  EXPECT_EQ("O_WRONLY|O_ASYNC", OpenFlagsToString(O_WRONLY | O_ASYNC));
  EXPECT_EQ("O_RDWR|O_CREAT|O_EXCL|O_TRUNC",
            OpenFlagsToString(O_RDWR | O_CREAT | O_EXCL | O_TRUNC));
  EXPECT_EQ("O_RDWR|0x78000000", OpenFlagsToString(O_RDWR | 0x78000000));

  EXPECT_EQ("INVALID_OPEN_MODE",
            OpenFlagsToString(O_RDONLY | O_WRONLY | O_RDWR));
}

TEST(UtilTest, ToSetFlagsToString) {
  EXPECT_EQ("0", ToSetFlagsToString(0));
  EXPECT_EQ("FUSE_SET_ATTR_SIZE", ToSetFlagsToString(FUSE_SET_ATTR_SIZE));
  EXPECT_EQ("FUSE_SET_ATTR_UID|FUSE_SET_ATTR_GID",
            ToSetFlagsToString(FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID));
  EXPECT_EQ("FUSE_SET_ATTR_ATIME|0x120000",
            ToSetFlagsToString(FUSE_SET_ATTR_ATIME | 0x120000));
}

TEST(UtilTest, IpAddressToString) {
  EXPECT_EQ("", IpAddressToString({}));
  EXPECT_EQ("", IpAddressToString({1}));
  EXPECT_EQ("", IpAddressToString({1, 2, 3, 4, 5}));

  EXPECT_EQ("0.0.0.0", IpAddressToString({0, 0, 0, 0}));
  EXPECT_EQ("1.2.3.4", IpAddressToString({1, 2, 3, 4}));
  EXPECT_EQ("255.255.255.255", IpAddressToString({255, 255, 255, 255}));
}

}  // namespace
}  // namespace smbfs
