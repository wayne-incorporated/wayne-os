// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <string>

#include <base/files/scoped_temp_dir.h>
#include <base/strings/utf_string_conversions.h>
#include <gtest/gtest.h>

#include "arc/container/obb-mounter/util.h"

namespace fat {

TEST(UtilTest, AppendLongFileNameCharactersReversed) {
  // 20 characters: 13 characters for slot2, 7 for slot1.
  std::u16string str = u"0123456789abcdef.txt";
  msdos_dir_slot slot1 = {}, slot2 = {};
  // The last slot comes first.
  memcpy(slot2.name0_4, str.c_str(), sizeof(slot2.name0_4));
  memcpy(slot2.name5_10, str.c_str() + 5, sizeof(slot2.name5_10));
  memcpy(slot2.name11_12, str.c_str() + 11, sizeof(slot2.name11_12));
  memcpy(slot1.name0_4, str.c_str() + 13, sizeof(slot1.name0_4));
  memcpy(slot1.name5_10, str.c_str() + 18, sizeof(char16_t) * 2);

  std::u16string buf;
  AppendLongFileNameCharactersReversed(slot1, &buf);
  ASSERT_EQ(13, buf.size());
  AppendLongFileNameCharactersReversed(slot2, &buf);
  ASSERT_EQ(13 * 2, buf.size());
  // Characters are reversed.
  std::reverse(buf.begin(), buf.end());
  // Compare with the string.
  EXPECT_EQ(0, buf[str.size()]);  // Null-terminated.
  EXPECT_EQ(str, buf.substr(0, str.size()));

  // ID == 0x40 means starting a new name.
  slot1.id = 0x40;
  AppendLongFileNameCharactersReversed(slot1, &buf);
  // The buffer was cleared before appending characters.
  EXPECT_EQ(13, buf.size());
}

TEST(UtilTest, ReadFileAllocationTable) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::File file;
  file.Initialize(
      temp_dir.GetPath().AppendASCII("test"),
      base::File::FLAG_CREATE | base::File::FLAG_READ | base::File::FLAG_WRITE);
  ASSERT_TRUE(file.IsValid());

  // Test FAT 12.
  // 0x123, 0x456, 0x789, EOF
  const int64_t fat_start = 0x100;
  const uint8_t data12[] = {0x23, 0x61, 0x45, 0x89, 0xf7, 0xff};
  EXPECT_EQ(file.Write(fat_start, reinterpret_cast<const char*>(data12),
                       sizeof(data12)),
            sizeof(data12));
  EXPECT_EQ(0x123,
            ReadFileAllocationTable(&file, FatType::FAT_12, fat_start, 0));
  EXPECT_EQ(0x456,
            ReadFileAllocationTable(&file, FatType::FAT_12, fat_start, 1));
  EXPECT_EQ(0x789,
            ReadFileAllocationTable(&file, FatType::FAT_12, fat_start, 2));
  EXPECT_EQ(kInvalidValue,
            ReadFileAllocationTable(&file, FatType::FAT_12, fat_start, 3));

  // Test FAT 16.
  const __le16 data16[] = {htole16(0x1234), htole16(0x5678), htole16(0x9abc),
                           htole16(0xffff)};
  EXPECT_EQ(file.Write(fat_start, reinterpret_cast<const char*>(data16),
                       sizeof(data16)),
            sizeof(data16));
  EXPECT_EQ(0x1234,
            ReadFileAllocationTable(&file, FatType::FAT_16, fat_start, 0));
  EXPECT_EQ(0x5678,
            ReadFileAllocationTable(&file, FatType::FAT_16, fat_start, 1));
  EXPECT_EQ(0x9abc,
            ReadFileAllocationTable(&file, FatType::FAT_16, fat_start, 2));
  EXPECT_EQ(kInvalidValue,
            ReadFileAllocationTable(&file, FatType::FAT_16, fat_start, 3));

  // Test FAT 32.
  const __le32 data32[] = {htole32(0x01234567), htole32(0x089abcde),
                           htole32(0x0f123456), htole32(0xffffffff)};
  EXPECT_EQ(file.Write(fat_start, reinterpret_cast<const char*>(data32),
                       sizeof(data32)),
            sizeof(data32));
  EXPECT_EQ(0x01234567,
            ReadFileAllocationTable(&file, FatType::FAT_32, fat_start, 0));
  EXPECT_EQ(0x089abcde,
            ReadFileAllocationTable(&file, FatType::FAT_32, fat_start, 1));
  EXPECT_EQ(0x0f123456,
            ReadFileAllocationTable(&file, FatType::FAT_32, fat_start, 2));
  EXPECT_EQ(kInvalidValue,
            ReadFileAllocationTable(&file, FatType::FAT_32, fat_start, 3));
}

}  // namespace fat
