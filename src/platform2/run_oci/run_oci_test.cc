// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "run_oci/container_config_parser.h"

#include <sys/mount.h>

#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "run_oci/run_oci_utils.h"

namespace {

TEST(OciUtilsTest, TestGetMountpointsUnder) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  constexpr char kSelfProcMountsData[] =
      R"(
/dev/root / ext2 rw 0 0
devtmpfs /dev devtmpfs rw 0 0
none /proc proc rw,nosuid,nodev,noexec,relatime 0 0
none /sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0
none /sys/fs/selinux selinuxfs rw,nosuid,noexec,relatime 0 0
tmp /tmp tmpfs rw,seclabel,nodev,relatime 0 0
run /run tmpfs rw,seclabel,nosuid,nodev,noexec,relatime,mode=755 0 0
/dev/loop1 /run/containers/android-master-33lymv/rootfs/root squashfs ro 0 0
/dev/loop2 /run/containers/android-master-33lymv/vendor squashfs ro 0 0
tmpfs /run/containers/android-master-33lymv/rootfs/root/dev )"
      R"(tmpfs rw,seclabel,nosuid,relatime,mode=755,uid=655360,gid=655360 0 0
debugfs /run/sync_export debugfs rw 0 0
  )";
  base::FilePath mounts = temp_dir.GetPath().Append("mounts");
  EXPECT_EQ(
      base::WriteFile(mounts, kSelfProcMountsData, sizeof(kSelfProcMountsData)),
      sizeof(kSelfProcMountsData));

  std::vector<run_oci::Mountpoint> mountpoints = run_oci::GetMountpointsUnder(
      base::FilePath("/run/containers/android-master-33lymv"), mounts);

  EXPECT_EQ(
      mountpoints,
      (std::vector<run_oci::Mountpoint>{
          run_oci::Mountpoint{
              base::FilePath(
                  "/run/containers/android-master-33lymv/rootfs/root"),
              MS_RDONLY, std::string()},
          run_oci::Mountpoint{
              base::FilePath("/run/containers/android-master-33lymv/vendor"),
              MS_RDONLY, std::string()},
          run_oci::Mountpoint{
              base::FilePath(
                  "/run/containers/android-master-33lymv/rootfs/root/dev"),
              MS_NOSUID | MS_RELATIME,
              "seclabel,mode=755,uid=655360,gid=655360"}}));
}

}  // namespace
