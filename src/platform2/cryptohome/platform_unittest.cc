// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/platform.h"

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <linux/fs.h>

#include <fcntl.h>
#include <string>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/util/get_random_suffix.h"

using base::FilePath;

namespace cryptohome {

class PlatformTest : public ::testing::Test {
 public:
  virtual ~PlatformTest() {}

 protected:
  FilePath GetTempName() {
    FilePath temp_directory;
    EXPECT_TRUE(base::GetTempDir(&temp_directory));
    return temp_directory.Append(GetRandomSuffix());
  }

  Platform platform_;
};

TEST_F(PlatformTest, SyncFileHasValidReturnCodes) {
  const FilePath filename(GetTempName());
  const FilePath dirname(GetTempName());
  platform_.CreateDirectory(dirname);
  EXPECT_FALSE(platform_.SyncFile(dirname));
  EXPECT_FALSE(platform_.SyncFile(filename));
  EXPECT_TRUE(platform_.WriteStringToFile(filename, "bla"));
  EXPECT_TRUE(platform_.SyncFile(filename));
  platform_.DeleteFile(filename);
  platform_.DeletePathRecursively(dirname);
}

TEST_F(PlatformTest, SyncDirectoryHasValidReturnCodes) {
  const FilePath filename(GetTempName());
  const FilePath dirname(GetTempName());
  platform_.WriteStringToFile(filename, "bla");
  EXPECT_FALSE(platform_.SyncDirectory(filename));
  EXPECT_FALSE(platform_.SyncDirectory(dirname));
  EXPECT_TRUE(platform_.CreateDirectory(dirname));
  EXPECT_TRUE(platform_.SyncDirectory(dirname));
  platform_.DeleteFile(filename);
  platform_.DeletePathRecursively(dirname);
}

TEST_F(PlatformTest, HasExtendedFileAttribute) {
  const FilePath filename(GetTempName());
  const std::string content("blablabla");
  ASSERT_TRUE(platform_.WriteStringToFile(filename, content));
  const std::string name("user.foo");
  const std::string value("bar");

  ASSERT_EQ(0, setxattr(filename.value().c_str(), name.c_str(), value.c_str(),
                        value.length(), 0));

  EXPECT_TRUE(platform_.HasExtendedFileAttribute(filename, name));

  EXPECT_FALSE(
      platform_.HasExtendedFileAttribute(FilePath("/file_not_exist"), name));
  EXPECT_FALSE(
      platform_.HasExtendedFileAttribute(filename, "user.name_not_exist"));
  platform_.DeleteFile(filename);
}

TEST_F(PlatformTest, ListExtendedFileAttribute) {
  const FilePath filename(GetTempName());
  const std::string content("blablabla");
  ASSERT_TRUE(platform_.WriteStringToFile(filename, content));
  const std::string name("user.foo");
  const std::string value("bar");
  const std::string name2("user.foo2");
  const std::string value2("bar2");

  ASSERT_EQ(0, setxattr(filename.value().c_str(), name.c_str(), value.c_str(),
                        value.length(), 0));
  ASSERT_EQ(0, setxattr(filename.value().c_str(), name2.c_str(), value2.c_str(),
                        value2.length(), 0));

  std::vector<std::string> attrs;

  EXPECT_TRUE(platform_.ListExtendedFileAttributes(filename, &attrs));
  EXPECT_THAT(attrs, testing::UnorderedElementsAre(name, name2));

  attrs.clear();
  EXPECT_FALSE(platform_.ListExtendedFileAttributes(FilePath("/file_not_exist"),
                                                    &attrs));
  EXPECT_TRUE(attrs.empty());
  platform_.DeleteFile(filename);
}

TEST_F(PlatformTest, GetExtendedAttributeAsString) {
  const FilePath filename(GetTempName());
  const std::string content("blablabla");
  ASSERT_TRUE(platform_.WriteStringToFile(filename, content));
  const std::string name("user.foo");
  const std::string value("bar");

  ASSERT_EQ(0, setxattr(filename.value().c_str(), name.c_str(), value.c_str(),
                        value.length(), 0));

  std::string got;
  EXPECT_TRUE(platform_.GetExtendedFileAttributeAsString(filename, name, &got));
  EXPECT_EQ(value, got);

  EXPECT_FALSE(platform_.GetExtendedFileAttributeAsString(
      FilePath("/file_not_exist"), name, &got));
  EXPECT_FALSE(platform_.GetExtendedFileAttributeAsString(
      filename, "user.name_not_exist", &got));
  platform_.DeleteFile(filename);
}

TEST_F(PlatformTest, GetExtendedAttribute) {
  const FilePath filename(GetTempName());
  const std::string content("blablabla");
  ASSERT_TRUE(platform_.WriteStringToFile(filename, content));
  const std::string name("user.foo");
  const int value = 42;

  ASSERT_EQ(0, setxattr(filename.value().c_str(), name.c_str(), &value,
                        sizeof(value), 0));

  int got;
  EXPECT_TRUE(platform_.GetExtendedFileAttribute(
      filename, name, reinterpret_cast<char*>(&got), sizeof(got)));
  EXPECT_EQ(value, got);

  EXPECT_FALSE(platform_.GetExtendedFileAttribute(
      FilePath("/file_not_exist"), name, reinterpret_cast<char*>(&got),
      sizeof(got)));
  EXPECT_FALSE(platform_.GetExtendedFileAttribute(
      filename, "user.name_not_exist", reinterpret_cast<char*>(&got),
      sizeof(got)));
  EXPECT_FALSE(platform_.GetExtendedFileAttribute(
      filename, name, reinterpret_cast<char*>(&got), sizeof(got) - 1));
  EXPECT_FALSE(platform_.GetExtendedFileAttribute(
      filename, name, reinterpret_cast<char*>(&got), sizeof(got) + 1));
  platform_.DeleteFile(filename);
}

TEST_F(PlatformTest, SetExtendedAttribute) {
  const FilePath filename(GetTempName());
  const std::string content("blablabla");
  ASSERT_TRUE(platform_.WriteStringToFile(filename, content));
  const std::string name("user.foo");
  std::string value("bar");
  EXPECT_TRUE(platform_.SetExtendedFileAttribute(filename, name, value.c_str(),
                                                 value.length()));

  std::vector<char> got(value.length());
  EXPECT_EQ(value.length(), getxattr(filename.value().c_str(), name.c_str(),
                                     got.data(), value.length()));

  EXPECT_EQ(value, std::string(got.data(), got.size()));

  EXPECT_FALSE(platform_.SetExtendedFileAttribute(
      FilePath("/file_not_exist"), name, value.c_str(), sizeof(value)));
  platform_.DeleteFile(filename);
}

TEST_F(PlatformTest, RemoveExtendedAttribute) {
  const FilePath filename(GetTempName());
  const std::string content("blablabla");
  ASSERT_TRUE(platform_.WriteStringToFile(filename, content));
  const std::string name("user.foo");
  std::string value("bar");
  ASSERT_EQ(0, setxattr(filename.value().c_str(), name.c_str(), value.c_str(),
                        value.length(), 0));
  EXPECT_TRUE(platform_.RemoveExtendedFileAttribute(filename, name));
  EXPECT_EQ(-1, getxattr(filename.value().c_str(), name.c_str(), nullptr, 0));
  EXPECT_EQ(ENODATA, errno);

  EXPECT_FALSE(
      platform_.RemoveExtendedFileAttribute(FilePath("/file_not_exist"), name));
  EXPECT_FALSE(
      platform_.RemoveExtendedFileAttribute(filename, "attribute_not_exist"));
  platform_.DeleteFile(filename);
}

TEST_F(PlatformTest, GetExtFileAttributes) {
  const FilePath filename(GetTempName());
  const std::string content("blablabla");
  ASSERT_TRUE(platform_.WriteStringToFile(filename, content));

  int fd;
  ASSERT_GT(fd = HANDLE_EINTR(open(filename.value().c_str(), O_RDONLY)), 0);

  int flags;
  ASSERT_GE(ioctl(fd, FS_IOC_GETFLAGS, &flags), 0);
  flags |= FS_UNRM_FL | FS_NODUMP_FL;
  ASSERT_GE(ioctl(fd, FS_IOC_SETFLAGS, &flags), 0);

  int got;
  EXPECT_TRUE(platform_.GetExtFileAttributes(filename, &got));
  EXPECT_EQ(flags, got);
  close(fd);
  platform_.DeleteFile(filename);
}

TEST_F(PlatformTest, SetExtFileAttributes) {
  const FilePath filename(GetTempName());
  const std::string content("blablabla");
  ASSERT_TRUE(platform_.WriteStringToFile(filename, content));

  int flags = FS_UNRM_FL | FS_NODUMP_FL;
  EXPECT_TRUE(platform_.SetExtFileAttributes(filename, flags));

  int fd;
  ASSERT_GT(fd = HANDLE_EINTR(open(filename.value().c_str(), O_RDONLY)), 0);
  int new_flags;
  ASSERT_GE(ioctl(fd, FS_IOC_GETFLAGS, &new_flags), 0);

  EXPECT_EQ(flags, new_flags & flags);
  close(fd);
  platform_.DeleteFile(filename);
}

TEST_F(PlatformTest, HasNoDumpFileAttribute) {
  const FilePath filename(GetTempName());
  const std::string content("blablabla");
  ASSERT_TRUE(platform_.WriteStringToFile(filename, content));

  EXPECT_FALSE(platform_.HasNoDumpFileAttribute(filename));

  int fd;
  ASSERT_GT(fd = open(filename.value().c_str(), O_RDONLY), 0);
  EXPECT_TRUE(
      platform_.SetExtFileAttributes(filename, FS_UNRM_FL | FS_NODUMP_FL));
  EXPECT_TRUE(platform_.HasNoDumpFileAttribute(filename));
  close(fd);
  platform_.DeleteFile(filename);
}

TEST_F(PlatformTest, ReadMountInfoFileGood) {
  const base::FilePath mount_info(GetTempName());
  std::string mount_info_contents;

  mount_info_contents.append("73 24 179:1 /beg/uid1/mount/user ");
  mount_info_contents.append("/home/user/uid1 rw,nodev,relatime - ext4 ");
  mount_info_contents.append("/dev/mmcblk0p1 rw,commit=600,data=ordered");

  EXPECT_TRUE(platform_.WriteStringToFile(mount_info, mount_info_contents));
  platform_.set_mount_info_path(mount_info);

  std::vector<DecodedProcMountInfo> decoded_info =
      platform_.ReadMountInfoFile();
  EXPECT_EQ(decoded_info.size(), 1);
  EXPECT_EQ(decoded_info[0].root, "/beg/uid1/mount/user");
  EXPECT_EQ(decoded_info[0].mount_point, "/home/user/uid1");
  EXPECT_EQ(decoded_info[0].filesystem_type, "ext4");
  EXPECT_EQ(decoded_info[0].mount_source, "/dev/mmcblk0p1");
}

TEST_F(PlatformTest, ReadMountInfoFileCorruptedMountInfo) {
  const base::FilePath mount_info(GetTempName());
  std::string mount_info_contents;

  mount_info_contents.append("73 24 179:1 /beg/uid1/mount/user ");
  mount_info_contents.append("/home/user/uid1 rw,nodev,relatime hypen ext4 ");
  mount_info_contents.append("/dev/mmcblk0p1 rw,commit=600,data=ordered");

  EXPECT_TRUE(platform_.WriteStringToFile(mount_info, mount_info_contents));
  platform_.set_mount_info_path(mount_info);

  std::vector<DecodedProcMountInfo> decoded_info =
      platform_.ReadMountInfoFile();
  EXPECT_EQ(decoded_info.size(), 0);
}

TEST_F(PlatformTest, ReadMountInfoFileIncompleteMountInfo) {
  const base::FilePath mount_info(GetTempName());
  std::string mount_info_contents;

  mount_info_contents.append("73 24 179:1 /beg/uid1/mount/user ");

  EXPECT_TRUE(platform_.WriteStringToFile(mount_info, mount_info_contents));
  platform_.set_mount_info_path(mount_info);

  std::vector<DecodedProcMountInfo> decoded_info =
      platform_.ReadMountInfoFile();
  EXPECT_EQ(decoded_info.size(), 0);
}

TEST_F(PlatformTest, GetLoopDeviceMounts) {
  const base::FilePath mount_info(GetTempName());
  std::string mount_info_contents;

  mount_info_contents.append("73 24 179:1 /beg/uid1/mount/user ");
  mount_info_contents.append("/home/root/uid1 rw,nodev,relatime - ext4 ");
  mount_info_contents.append("/dev/loop7 rw,commit=600,data=ordered\n");
  mount_info_contents.append("73 24 179:1 /beg/uid1/mount/user ");
  mount_info_contents.append("/home/root/uid1 rw,nodev,relatime - ext4 ");
  mount_info_contents.append("/dev/mmcblk0p1 rw,commit=600,data=ordered\n");
  mount_info_contents.append("73 24 179:1 /beg/uid1/mount/user ");
  mount_info_contents.append("/home/user/uid2 rw,nodev,relatime - ext4 ");
  mount_info_contents.append("/dev/loop6 rw,commit=600,data=ordered\n");

  EXPECT_TRUE(platform_.WriteStringToFile(mount_info, mount_info_contents));

  platform_.set_mount_info_path(mount_info);

  std::multimap<const FilePath, const FilePath> mounts;
  EXPECT_TRUE(platform_.GetLoopDeviceMounts(&mounts));
  ASSERT_EQ(mounts.size(), 2);
  auto it = mounts.begin();
  EXPECT_EQ(it->first.value(), "/dev/loop6");
  EXPECT_EQ(it->second.value(), "/home/user/uid2");
  ++it;
  EXPECT_EQ(it->first.value(), "/dev/loop7");
  EXPECT_EQ(it->second.value(), "/home/root/uid1");

  /* Clean up. */
  EXPECT_TRUE(base::DeleteFile(mount_info));
}

TEST_F(PlatformTest, GetMountsBySourcePrefixExt4) {
  base::FilePath mount_info;
  FILE* fp;
  std::string filesystem, device_in, device_out, mount_info_contents;

  mount_info_contents.append("73 24 179:1 /beg/uid1/mount/user ");
  mount_info_contents.append("/home/user/uid1 rw,nodev,relatime - ext4 ");
  mount_info_contents.append("/dev/mmcblk0p1 rw,commit=600,data=ordered");

  fp = base::CreateAndOpenTemporaryStream(&mount_info).release();
  ASSERT_TRUE(fp != NULL);
  EXPECT_EQ(
      fwrite(mount_info_contents.c_str(), mount_info_contents.length(), 1, fp),
      1);
  EXPECT_EQ(fclose(fp), 0);

  platform_.set_mount_info_path(mount_info);

  /* Fails if item is missing. */
  std::multimap<const FilePath, const FilePath> mounts;
  EXPECT_FALSE(platform_.GetMountsBySourcePrefix(FilePath("monkey"), &mounts));

  /* Works normally. */
  mounts.clear();
  EXPECT_TRUE(platform_.GetMountsBySourcePrefix(FilePath("/beg"), &mounts));
  EXPECT_EQ(mounts.size(), 1);
  auto it = mounts.begin();
  EXPECT_EQ(it->first.value(), "/beg/uid1/mount/user");
  EXPECT_EQ(it->second.value(), "/home/user/uid1");

  /* Clean up. */
  EXPECT_TRUE(base::DeleteFile(mount_info));
}

TEST_F(PlatformTest, GetMountsBySourcePrefixECryptFs) {
  base::FilePath mount_info;
  FILE* fp;
  std::string filesystem, device_in, device_out, mount_info_contents;

  mount_info_contents.append("84 24 0:29 /user /home/user/uid2 ");
  mount_info_contents.append("rw,nosuid,nodev,noexec,relatime - ecryptfs ");
  mount_info_contents.append("/beg/uid2/vault rw,ecryp...");

  fp = base::CreateAndOpenTemporaryStream(&mount_info).release();
  ASSERT_TRUE(fp != NULL);
  EXPECT_EQ(
      fwrite(mount_info_contents.c_str(), mount_info_contents.length(), 1, fp),
      1);
  EXPECT_EQ(fclose(fp), 0);

  platform_.set_mount_info_path(mount_info);

  /* Fails if item is missing. */
  std::multimap<const FilePath, const FilePath> mounts;
  EXPECT_FALSE(platform_.GetMountsBySourcePrefix(FilePath("monkey"), &mounts));

  /* Works normally. */
  mounts.clear();
  EXPECT_TRUE(platform_.GetMountsBySourcePrefix(FilePath("/beg"), &mounts));
  EXPECT_EQ(mounts.size(), 1);
  auto it = mounts.begin();
  EXPECT_EQ(it->first.value(), "/beg/uid2/vault");
  EXPECT_EQ(it->second.value(), "/home/user/uid2");

  /* Clean up. */
  EXPECT_TRUE(base::DeleteFile(mount_info));
}

TEST_F(PlatformTest, CreateSymbolicLink) {
  const base::FilePath link(GetTempName());
  const base::FilePath target(GetTempName());
  const base::FilePath existing_file(GetTempName());
  ASSERT_TRUE(platform_.TouchFileDurable(existing_file));
  EXPECT_TRUE(platform_.CreateSymbolicLink(link, target));
  EXPECT_FALSE(platform_.CreateSymbolicLink(existing_file, target));
  base::FilePath read_target;
  ASSERT_TRUE(base::ReadSymbolicLink(link, &read_target));
  EXPECT_EQ(target.value(), read_target.value());
}

TEST_F(PlatformTest, ReadLink) {
  const base::FilePath valid_link(GetTempName());
  const base::FilePath not_link(GetTempName());
  const base::FilePath target(GetTempName());
  ASSERT_TRUE(base::CreateSymbolicLink(target, valid_link));
  ASSERT_TRUE(platform_.TouchFileDurable(not_link));
  base::FilePath read_target;
  EXPECT_TRUE(platform_.ReadLink(valid_link, &read_target));
  EXPECT_EQ(target.value(), read_target.value());
  EXPECT_FALSE(platform_.ReadLink(not_link, &read_target));
}

TEST_F(PlatformTest, SetFileTimes) {
  struct timespec atime1 = {123, 45};
  struct timespec mtime1 = {234, 56};
  struct timespec atime2 = {345, 67};
  struct timespec mtime2 = {456, 78};
  const base::FilePath regular_file(GetTempName());
  const base::FilePath link(GetTempName());
  ASSERT_TRUE(platform_.TouchFileDurable(regular_file));
  ASSERT_TRUE(platform_.CreateSymbolicLink(link, regular_file));

  EXPECT_TRUE(platform_.SetFileTimes(regular_file, atime1, mtime1, true));
  base::stat_wrapper_t stat;
  ASSERT_TRUE(platform_.Stat(regular_file, &stat));
  EXPECT_EQ(atime1.tv_sec, stat.st_atim.tv_sec);
  EXPECT_EQ(atime1.tv_nsec, stat.st_atim.tv_nsec);
  EXPECT_EQ(mtime1.tv_sec, stat.st_mtim.tv_sec);
  EXPECT_EQ(mtime1.tv_nsec, stat.st_mtim.tv_nsec);

  EXPECT_TRUE(platform_.SetFileTimes(link, atime2, mtime2, true));
  ASSERT_TRUE(platform_.Stat(regular_file, &stat));
  EXPECT_EQ(atime2.tv_sec, stat.st_atim.tv_sec);
  EXPECT_EQ(atime2.tv_nsec, stat.st_atim.tv_nsec);
  EXPECT_EQ(mtime2.tv_sec, stat.st_mtim.tv_sec);
  EXPECT_EQ(mtime2.tv_nsec, stat.st_mtim.tv_nsec);
  ASSERT_TRUE(platform_.Stat(link, &stat));
  EXPECT_NE(atime2.tv_sec, stat.st_atim.tv_sec);
  EXPECT_NE(atime2.tv_nsec, stat.st_atim.tv_nsec);
  EXPECT_NE(mtime2.tv_sec, stat.st_mtim.tv_sec);
  EXPECT_NE(mtime2.tv_nsec, stat.st_mtim.tv_nsec);
}

TEST_F(PlatformTest, SendFile) {
  const base::FilePath from(GetTempName());
  const base::FilePath to(GetTempName());
  const std::string contents = "0123456789";
  ASSERT_TRUE(platform_.WriteStringToFile(from, contents));

  const int offset = 5;
  const int read_size = contents.length() - offset;
  base::File from_file(from, base::File::FLAG_OPEN | base::File::FLAG_READ);
  base::File to_file(to, base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  EXPECT_TRUE(platform_.SendFile(to_file.GetPlatformFile(),
                                 from_file.GetPlatformFile(), offset,
                                 read_size));
  std::string to_contents;
  ASSERT_TRUE(platform_.ReadFileToString(to, &to_contents));
  EXPECT_EQ(contents.substr(offset, read_size), to_contents);

  EXPECT_FALSE(
      platform_.SendFile(-1, from_file.GetPlatformFile(), offset, read_size));
  EXPECT_FALSE(platform_.SendFile(to_file.GetPlatformFile(),
                                  from_file.GetPlatformFile(), offset,
                                  read_size + 1));
  platform_.DeleteFile(from);
  platform_.DeleteFile(to);
}

TEST_F(PlatformTest, CreateSparseFile) {
  const base::FilePath sparse_name(GetTempName());
  int64_t file_size = 1024 * 32;
  EXPECT_TRUE(platform_.CreateSparseFile(sparse_name, file_size));
  base::File sparse_file(sparse_name,
                         base::File::FLAG_OPEN | base::File::FLAG_READ);
  EXPECT_EQ(file_size, sparse_file.GetLength());
  base::stat_wrapper_t stat;
  EXPECT_TRUE(platform_.Stat(sparse_name, &stat));
  // No blocks allocated for a sparse file.
  EXPECT_EQ(0, stat.st_blocks);
  platform_.DeleteFile(sparse_name);
}

}  // namespace cryptohome
