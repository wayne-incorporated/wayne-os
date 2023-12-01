// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/storage_balloon.h"

#include <sys/statvfs.h>
#include <sys/vfs.h>

#include <string>
#include <unordered_map>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace brillo {

class FakeStorageBalloon : public StorageBalloon {
 public:
  FakeStorageBalloon(uint64_t remaining_size, const base::FilePath& path)
      : StorageBalloon(path), remaining_size_(remaining_size) {}

  std::string Getxattr(const char* name) {
    return xattr_map_[std::string(name)];
  }

 protected:
  bool Fallocate(int64_t offset, int64_t len) override {
    file_size_ += len;
    remaining_size_ -= len;
    return true;
  }

  bool Ftruncate(int64_t len) override {
    remaining_size_ += (file_size_ - len);
    file_size_ = len;
    return true;
  }

  bool FstatFs(struct statfs* buf) override {
    buf->f_bsize = 4096;
    buf->f_blocks = (remaining_size_ + file_size_) / 4096;
    buf->f_bfree = remaining_size_ / 4096;
    return true;
  }

  bool Fstat(struct stat* buf) override {
    buf->st_blocks = file_size_ / 512;
    return true;
  }

  bool Setxattr(const char* name, const std::string& value) override {
    xattr_map_[std::string(name)] = value;
    return true;
  }

 private:
  uint64_t file_size_ = 0;
  uint64_t remaining_size_;

  std::unordered_map<std::string, std::string> xattr_map_;
};

TEST(StorageBalloon, InvalidPath) {
  FakeStorageBalloon f(4096, base::FilePath("/a/b/c"));
  EXPECT_EQ(f.IsValid(), false);
}

TEST(StorageBalloon, ValidPath) {
  base::ScopedTempDir dir;

  ASSERT_TRUE(dir.CreateUniqueTempDir());
  FakeStorageBalloon f(4096, dir.GetPath());
  EXPECT_EQ(f.IsValid(), true);
}

TEST(StorageBalloonTest, FullInflation) {
  base::ScopedTempDir dir;

  ASSERT_TRUE(dir.CreateUniqueTempDir());
  FakeStorageBalloon f(100 * 4096, dir.GetPath());
  EXPECT_EQ(f.IsValid(), true);

  EXPECT_TRUE(f.Adjust(5 * 4096));
  EXPECT_EQ(f.GetCurrentBalloonSize(), 95 * 4096);

  EXPECT_TRUE(f.Adjust(4096));
  EXPECT_EQ(f.GetCurrentBalloonSize(), 99 * 4096);
}

TEST(StorageBalloonTest, FullDeflation) {
  base::ScopedTempDir dir;

  ASSERT_TRUE(dir.CreateUniqueTempDir());
  FakeStorageBalloon f(100 * 4096, dir.GetPath());
  EXPECT_EQ(f.IsValid(), true);

  EXPECT_TRUE(f.Adjust(5 * 4096));
  EXPECT_EQ(f.GetCurrentBalloonSize(), 95 * 4096);

  EXPECT_TRUE(f.Deflate());
  EXPECT_EQ(f.GetCurrentBalloonSize(), 0);
}

TEST(StorageBalloonTest, Adjustment) {
  base::ScopedTempDir dir;

  ASSERT_TRUE(dir.CreateUniqueTempDir());
  FakeStorageBalloon f(100 * 4096, dir.GetPath());
  EXPECT_EQ(f.IsValid(), true);

  EXPECT_TRUE(f.Adjust(1 * 4096));
  EXPECT_EQ(f.GetCurrentBalloonSize(), 99 * 4096);

  EXPECT_TRUE(f.Adjust(95 * 4096));
  EXPECT_EQ(f.GetCurrentBalloonSize(), 5 * 4096);
}

TEST(StorageBalloonTest, DisableProvisioning) {
  base::ScopedTempDir dir;

  ASSERT_TRUE(dir.CreateUniqueTempDir());
  FakeStorageBalloon f(100 * 4096, dir.GetPath());
  EXPECT_EQ(f.IsValid(), true);

  EXPECT_TRUE(f.DisableProvisioning());
  EXPECT_EQ(f.Getxattr("trusted.provision"), "n");
}

}  // namespace brillo
