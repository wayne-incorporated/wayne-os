// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "brillo/blkdev_utils/disk_iostat.h"

namespace brillo {

// Tests that all fields 4.18+ kernel are populated.
TEST(DiskIoStat, Extended) {
  constexpr char kPath[] = "testdata/disk_iostat/sys/block/nvme0n1";
  DiskIoStat iostat{base::FilePath(kPath)};
  auto snap = iostat.GetSnapshot();

  ASSERT_TRUE(snap.has_value());
  EXPECT_EQ(144016, snap->GetReadTime().InMilliseconds());
  EXPECT_EQ(22155414, snap->GetWriteTime().InMilliseconds());
  EXPECT_EQ(35505772, snap->GetReadSectors());
  EXPECT_EQ(665648234, snap->GetWrittenSectors());
  EXPECT_EQ(4646032, snap->GetIoTime().InMilliseconds());
  ASSERT_TRUE(snap->GetDiscardTime().has_value());
  EXPECT_EQ(200092, snap->GetDiscardTime().value().InMilliseconds());
}

// Tests that some fields are correctly missing on <4.18 kernel.
TEST(DiskIoStat, Legacy) {
  constexpr char kPath[] = "testdata/disk_iostat/sys/block/mmcblk0";
  DiskIoStat iostat{base::FilePath(kPath)};
  auto snap = iostat.GetSnapshot();

  ASSERT_TRUE(snap.has_value());
  EXPECT_EQ(184023, snap->GetReadTime().InMilliseconds());
  EXPECT_EQ(13849275, snap->GetWriteTime().InMilliseconds());
  EXPECT_EQ(84710472, snap->GetReadSectors());
  EXPECT_EQ(7289304, snap->GetWrittenSectors());
  EXPECT_EQ(7392983, snap->GetIoTime().InMilliseconds());
  EXPECT_FALSE(snap->GetDiscardTime().has_value());
}

// Tests missing stat file.
TEST(DiskIoStat, NotFound) {
  constexpr char kPath[] = "testdata/disk_iostat/sys/block/sda1";
  DiskIoStat iostat{base::FilePath(kPath)};
  ASSERT_FALSE(iostat.GetSnapshot().has_value());
}

// Tests mis-formatted stat file.
TEST(DiskIoStat, WrongFormat) {
  constexpr char kPath[] = "testdata/disk_iostat/sys/block/nvme0n2";
  DiskIoStat iostat{base::FilePath(kPath)};
  ASSERT_FALSE(iostat.GetSnapshot().has_value());
}

TEST(DiskIoStat, SnapshotValidity) {
  constexpr char kPath[] = "testdata/disk_iostat/sys/block/mmcblk0";
  DiskIoStat iostat{base::FilePath(kPath)};

  EXPECT_FALSE(DiskIoStat::Snapshot().IsValid());
  EXPECT_TRUE(iostat.GetSnapshot()->IsValid());
}

TEST(DiskIoStat, SnapshotDelta) {
  DiskIoStat::Stat s1 = {
      .read_ios = 11,
      .read_merges = 12,
      .read_sectors = 13,
      .read_ticks = 14,
      .write_ios = 15,
      .write_merges = 16,
      .write_sectors = 17,
      .write_ticks = 18,
      .in_flight = 19,
      .io_ticks = 20,
      .time_in_queue = 21,
      .discard_ios = 22,
      .discard_merges = 23,
      .discard_sectors = std::nullopt,
      .discard_ticks = std::nullopt,
  };

  DiskIoStat::Stat s2 = {
      .read_ios = 111,
      .read_merges = 212,
      .read_sectors = 313,
      .read_ticks = 414,
      .write_ios = 515,
      .write_merges = 616,
      .write_sectors = 717,
      .write_ticks = 818,
      .in_flight = 919,
      .io_ticks = 1020,
      .time_in_queue = 1121,
      .discard_ios = 1222,
      .discard_merges = std::nullopt,
      .discard_sectors = 1424,
      .discard_ticks = std::nullopt,
  };

  base::Time t1 = base::Time::UnixEpoch();
  DiskIoStat::Snapshot snap1(t1.since_origin(), s1);
  base::Time t2 = base::Time::UnixEpoch() + base::Milliseconds(100);
  DiskIoStat::Snapshot snap2(t2.since_origin(), s2);
  DiskIoStat::Delta delta = snap2.Delta(snap1);
  DiskIoStat::Stat delta_stat = delta->GetRawStat();

  EXPECT_EQ(delta->GetTimestamp(), base::Milliseconds(100));
  EXPECT_EQ(delta_stat.read_ios, 100);
  EXPECT_EQ(delta_stat.read_merges, 200);
  EXPECT_EQ(delta_stat.read_sectors, 300);
  EXPECT_EQ(delta_stat.read_ticks, 400);
  EXPECT_EQ(delta_stat.write_ios, 500);
  EXPECT_EQ(delta_stat.write_merges, 600);
  EXPECT_EQ(delta_stat.write_sectors, 700);
  EXPECT_EQ(delta_stat.write_ticks, 800);
  EXPECT_EQ(delta_stat.in_flight, 900);
  EXPECT_EQ(delta_stat.io_ticks, 1000);
  EXPECT_EQ(delta_stat.time_in_queue, 1100);
  EXPECT_EQ(delta_stat.discard_ios, 1200);
  EXPECT_EQ(delta_stat.discard_merges, std::nullopt);
  EXPECT_EQ(delta_stat.discard_sectors, std::nullopt);
  EXPECT_EQ(delta_stat.discard_ticks, std::nullopt);
}

}  // namespace brillo
