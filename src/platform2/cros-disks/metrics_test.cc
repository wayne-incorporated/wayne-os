// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/metrics.h"

#include <gtest/gtest.h>

namespace cros_disks {

class MetricsTest : public ::testing::Test {
 protected:
  Metrics metrics_;
};

TEST_F(MetricsTest, GetArchiveType) {
  EXPECT_EQ(Metrics::kArchiveUnknown, metrics_.GetArchiveType(""));
  EXPECT_EQ(Metrics::kArchiveUnknown, metrics_.GetArchiveType("/foo/bar.txt"));
  EXPECT_EQ(Metrics::kArchiveUnknown, metrics_.GetArchiveType("/foo/bar"));
  EXPECT_EQ(Metrics::kArchiveZip, metrics_.GetArchiveType("/foo/bar.zip"));
  EXPECT_EQ(Metrics::kArchiveZip, metrics_.GetArchiveType("/foo/bar.tar.zip"));
  EXPECT_EQ(Metrics::kArchiveZip, metrics_.GetArchiveType("/foo/bar.Zip"));
  EXPECT_EQ(Metrics::kArchiveZip, metrics_.GetArchiveType("/foo/bar.ZIP"));
  EXPECT_EQ(Metrics::kArchiveRar, metrics_.GetArchiveType("/foo/bar.rar"));
  EXPECT_EQ(Metrics::kArchiveTar, metrics_.GetArchiveType("/foo/bar.tar"));
  EXPECT_EQ(Metrics::kArchiveBzip2,
            metrics_.GetArchiveType("/foo/bar.txt.bz2"));
  EXPECT_EQ(Metrics::kArchiveBzip2, metrics_.GetArchiveType("/foo/bar.bz2"));
  EXPECT_EQ(Metrics::kArchiveBzip2, metrics_.GetArchiveType("/foo/bar.txt.bz"));
  EXPECT_EQ(Metrics::kArchiveBzip2, metrics_.GetArchiveType("/foo/bar.bz"));
  EXPECT_EQ(Metrics::kArchiveTarBzip2,
            metrics_.GetArchiveType("/foo/bar.tar.bz2"));
  EXPECT_EQ(Metrics::kArchiveTarBzip2,
            metrics_.GetArchiveType("/foo/bar.tar.bz"));
  EXPECT_EQ(Metrics::kArchiveTarBzip2,
            metrics_.GetArchiveType("/foo/bar.tbz2"));
  EXPECT_EQ(Metrics::kArchiveTarBzip2, metrics_.GetArchiveType("/foo/bar.tbz"));
  EXPECT_EQ(Metrics::kArchiveTarBzip2, metrics_.GetArchiveType("/foo/bar.tz2"));
  EXPECT_EQ(Metrics::kArchiveTarBzip2, metrics_.GetArchiveType("/foo/bar.tb2"));
  EXPECT_EQ(Metrics::kArchiveGzip, metrics_.GetArchiveType("/foo/bar.txt.gz"));
  EXPECT_EQ(Metrics::kArchiveGzip, metrics_.GetArchiveType("/foo/bar.gz"));
  EXPECT_EQ(Metrics::kArchiveTarGzip,
            metrics_.GetArchiveType("/foo/bar.tar.gz"));
  EXPECT_EQ(Metrics::kArchiveTarGzip, metrics_.GetArchiveType("/foo/bar.tgz"));
  EXPECT_EQ(Metrics::kArchiveLz, metrics_.GetArchiveType("/foo/bar.lz"));
  EXPECT_EQ(Metrics::kArchiveTarLz, metrics_.GetArchiveType("/foo/bar.tar.lz"));
  EXPECT_EQ(Metrics::kArchiveLzma,
            metrics_.GetArchiveType("/foo/bar.txt.lzma"));
  EXPECT_EQ(Metrics::kArchiveLzma, metrics_.GetArchiveType("/foo/bar.lzma"));
  EXPECT_EQ(Metrics::kArchiveTarLzma,
            metrics_.GetArchiveType("/foo/bar.tar.lzma"));
  EXPECT_EQ(Metrics::kArchiveTarLzma,
            metrics_.GetArchiveType("/foo/bar.tlzma"));
  EXPECT_EQ(Metrics::kArchiveTarLzma, metrics_.GetArchiveType("/foo/bar.tlz"));
  EXPECT_EQ(Metrics::kArchiveXz, metrics_.GetArchiveType("/foo/bar.txt.xz"));
  EXPECT_EQ(Metrics::kArchiveXz, metrics_.GetArchiveType("/foo/bar.xz"));
  EXPECT_EQ(Metrics::kArchiveTarXz, metrics_.GetArchiveType("/foo/bar.tar.xz"));
  EXPECT_EQ(Metrics::kArchiveTarXz, metrics_.GetArchiveType("/foo/bar.txz"));
  EXPECT_EQ(Metrics::kArchiveZ, metrics_.GetArchiveType("/foo/bar.txt.z"));
  EXPECT_EQ(Metrics::kArchiveZ, metrics_.GetArchiveType("/foo/bar.z"));
  EXPECT_EQ(Metrics::kArchiveTarZ, metrics_.GetArchiveType("/foo/bar.tar.z"));
  EXPECT_EQ(Metrics::kArchiveTarZ, metrics_.GetArchiveType("/foo/bar.tar.Z"));
  EXPECT_EQ(Metrics::kArchiveTarZ, metrics_.GetArchiveType("/foo/bar.taz"));
  EXPECT_EQ(Metrics::kArchiveTarZ, metrics_.GetArchiveType("/foo/bar.taZ"));
  EXPECT_EQ(Metrics::kArchiveTarZ, metrics_.GetArchiveType("/foo/bar.tz"));
  EXPECT_EQ(Metrics::kArchiveTarZ, metrics_.GetArchiveType("/foo/bar.tZ"));
  EXPECT_EQ(Metrics::kArchiveZst, metrics_.GetArchiveType("/foo/bar.txt.zst"));
  EXPECT_EQ(Metrics::kArchiveZst, metrics_.GetArchiveType("/foo/bar.zst"));
  EXPECT_EQ(Metrics::kArchiveTarZst,
            metrics_.GetArchiveType("/foo/bar.tar.zst"));
  EXPECT_EQ(Metrics::kArchiveTarZst, metrics_.GetArchiveType("/foo/bar.tzst"));
}

TEST_F(MetricsTest, GetFilesystemType) {
  EXPECT_EQ(Metrics::kFilesystemUnknown, metrics_.GetFilesystemType(""));
  EXPECT_EQ(Metrics::kFilesystemVFAT, metrics_.GetFilesystemType("vfat"));
  EXPECT_EQ(Metrics::kFilesystemExFAT, metrics_.GetFilesystemType("exfat"));
  EXPECT_EQ(Metrics::kFilesystemNTFS, metrics_.GetFilesystemType("ntfs"));
  EXPECT_EQ(Metrics::kFilesystemHFSPlus, metrics_.GetFilesystemType("hfsplus"));
  EXPECT_EQ(Metrics::kFilesystemExt2, metrics_.GetFilesystemType("ext2"));
  EXPECT_EQ(Metrics::kFilesystemExt3, metrics_.GetFilesystemType("ext3"));
  EXPECT_EQ(Metrics::kFilesystemExt4, metrics_.GetFilesystemType("ext4"));
  EXPECT_EQ(Metrics::kFilesystemISO9660, metrics_.GetFilesystemType("iso9660"));
  EXPECT_EQ(Metrics::kFilesystemUDF, metrics_.GetFilesystemType("udf"));
  EXPECT_EQ(Metrics::kFilesystemOther, metrics_.GetFilesystemType("xfs"));
  EXPECT_EQ(Metrics::kFilesystemOther, metrics_.GetFilesystemType("btrfs"));
}

}  // namespace cros_disks
