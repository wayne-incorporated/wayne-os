// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "swap_management/swap_tool.h"

#include <limits>
#include <utility>

#include <absl/strings/str_cat.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using testing::_;
using testing::DoAll;
using testing::ElementsAre;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;

namespace swap_management {
namespace {
const char kSwapsNoZram[] =
    "Filename                               "
    " Type            Size            "
    "Used            Priority\n";
const char kMeminfoMemTotal8G[] = R"(MemTotal:        8144424 kB
MemFree:         5712260 kB
MemAvailable:    6368308 kB
Buffers:           64092 kB
Cached:          1045820 kB
SwapCached:            0 kB
Active:          1437424 kB
Inactive:         493512 kB
Active(anon):     848464 kB
Inactive(anon):    63600 kB
Active(file):     588960 kB
Inactive(file):   429912 kB
Unevictable:       68676 kB
Mlocked:           40996 kB
SwapTotal:      16288844 kB
SwapFree:       16288844 kB
Dirty:               380 kB
Writeback:             0 kB
AnonPages:        889736 kB
Mapped:           470060 kB
Shmem:             91040 kB
KReclaimable:      87488 kB
Slab:             174412 kB
SReclaimable:      87488 kB
SUnreclaim:        86924 kB
KernelStack:        9056 kB
PageTables:        18120 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:    20361056 kB
Committed_AS:    5581424 kB
VmallocTotal:   34359738367 kB
VmallocUsed:      145016 kB
VmallocChunk:          0 kB
Percpu:             2976 kB
AnonHugePages:     40960 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
FileHugePages:         0 kB
FilePmdMapped:         0 kB
DirectMap4k:      188268 kB
DirectMap2M:     8200192 kB)";
const char kZramDisksize8G[] = "16679780352";
const char kChromeosLowMemMargin8G[] = "413 3181";
}  // namespace

class MockSwapToolUtil : public swap_management::SwapToolUtil {
 public:
  MockSwapToolUtil() = default;
  MockSwapToolUtil& operator=(const MockSwapToolUtil&) = delete;
  MockSwapToolUtil(const MockSwapToolUtil&) = delete;

  MOCK_METHOD(absl::Status,
              RunProcessHelper,
              (const std::vector<std::string>& commands),
              (override));
  MOCK_METHOD(absl::Status,
              RunProcessHelper,
              (const std::vector<std::string>& commands, std::string* output),
              (override));
  MOCK_METHOD(absl::Status,
              WriteFile,
              (const base::FilePath& path, const std::string& data),
              (override));
  MOCK_METHOD(absl::Status,
              ReadFileToStringWithMaxSize,
              (const base::FilePath& path,
               std::string* contents,
               size_t max_size),
              (override));
  MOCK_METHOD(absl::Status,
              ReadFileToString,
              (const base::FilePath& path, std::string* contents),
              (override));
  MOCK_METHOD(absl::Status,
              DeleteFile,
              (const base::FilePath& path),
              (override));
  MOCK_METHOD(absl::Status,
              PathExists,
              (const base::FilePath& path),
              (override));
  MOCK_METHOD(absl::Status,
              Fallocate,
              (const base::FilePath& path, size_t size),
              (override));
  MOCK_METHOD(absl::Status,
              CreateDirectory,
              (const base::FilePath& path),
              (override));
  MOCK_METHOD(absl::Status,
              SetPosixFilePermissions,
              (const base::FilePath& path, int mode),
              (override));
  MOCK_METHOD(absl::Status,
              Mount,
              (const std::string& source,
               const std::string& target,
               const std::string& fs_type,
               uint64_t mount_flags,
               const std::string& data),
              (override));
  MOCK_METHOD(absl::Status, Umount, (const std::string& target), (override));
  MOCK_METHOD(absl::StatusOr<struct statfs>,
              GetStatfs,
              (const std::string& path),
              (override));
  MOCK_METHOD(absl::StatusOr<std::string>,
              GenerateRandHex,
              (size_t size),
              (override));
};

class SwapToolTest : public ::testing::Test {
 public:
  void SetUp() override {
    swap_tool_ = std::make_unique<SwapTool>();
    // Init SwapToolUtil and then replace with mocked one.
    SwapToolUtil::OverrideForTesting(&mock_util_);
  }

 protected:
  std::unique_ptr<SwapTool> swap_tool_;
  MockSwapToolUtil mock_util_;
};

TEST_F(SwapToolTest, SwapIsAlreadyOnOrOff) {
  EXPECT_CALL(mock_util_, ReadFileToString(base::FilePath("/proc/swaps"), _))
      .WillOnce(DoAll(SetArgPointee<1>(
                          absl::StrCat(kSwapsNoZram,
                                       "/dev/zram0                             "
                                       " partition       16288844        "
                                       "0               -2\n")),
                      Return(absl::OkStatus())));
  EXPECT_THAT(swap_tool_->SwapStart(), absl::OkStatus());

  EXPECT_CALL(mock_util_, ReadFileToString(base::FilePath("/proc/swaps"), _))
      .WillOnce(DoAll(
          SetArgPointee<1>(absl::StrCat(kSwapsNoZram,
                                        "/zram0                              "
                                        "partition       16288844        "
                                        "0               -2\n")),
          Return(absl::OkStatus())));
  EXPECT_THAT(swap_tool_->SwapStart(), absl::OkStatus());

  EXPECT_CALL(mock_util_, ReadFileToString(base::FilePath("/proc/swaps"), _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kSwapsNoZram), Return(absl::OkStatus())));
  EXPECT_THAT(swap_tool_->SwapStop(), absl::OkStatus());
}

TEST_F(SwapToolTest, SwapStartWithoutSwapEnabled) {
  // IsZramSwapOn
  EXPECT_CALL(mock_util_, ReadFileToString(base::FilePath("/proc/swaps"), _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kSwapsNoZram), Return(absl::OkStatus())));
  // GetMemTotal
  EXPECT_CALL(mock_util_, ReadFileToString(base::FilePath("/proc/meminfo"), _))
      .WillOnce(DoAll(SetArgPointee<1>(kMeminfoMemTotal8G),
                      Return(absl::OkStatus())));
  // InitializeMMTunables
  EXPECT_CALL(
      mock_util_,
      WriteFile(base::FilePath("/sys/kernel/mm/chromeos-low_mem/margin"),
                kChromeosLowMemMargin8G))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(
      mock_util_,
      WriteFile(base::FilePath("/proc/sys/vm/min_filelist_kbytes"), "1000000"))
      .WillOnce(Return(absl::OkStatus()));
  // GetZramSize
  EXPECT_CALL(mock_util_, ReadFileToStringWithMaxSize(
                              base::FilePath("/var/lib/swap/swap_size"), _, _))
      .WillOnce(Return(
          absl::NotFoundError("Failed to read /var/lib/swap/swap_size")));
  EXPECT_CALL(mock_util_,
              RunProcessHelper(ElementsAre("/sbin/modprobe", "zram")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_, WriteFile(base::FilePath("/sys/block/zram0/disksize"),
                                    kZramDisksize8G))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_,
              RunProcessHelper(ElementsAre("/sbin/mkswap", "/dev/zram0")))
      .WillOnce(Return(absl::OkStatus()));
  // EnableZramSwapping
  EXPECT_CALL(mock_util_,
              RunProcessHelper(ElementsAre("/sbin/swapon", "/dev/zram0")))
      .WillOnce(Return(absl::OkStatus()));

  EXPECT_THAT(swap_tool_->SwapStart(), absl::OkStatus());
}

TEST_F(SwapToolTest, SwapStartButSwapIsDisabled) {
  // IsZramSwapOn
  EXPECT_CALL(mock_util_, ReadFileToString(base::FilePath("/proc/swaps"), _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kSwapsNoZram), Return(absl::OkStatus())));
  // GetMemTotal
  EXPECT_CALL(mock_util_, ReadFileToString(base::FilePath("/proc/meminfo"), _))
      .WillOnce(DoAll(SetArgPointee<1>(kMeminfoMemTotal8G),
                      Return(absl::OkStatus())));
  // InitializeMMTunables
  EXPECT_CALL(
      mock_util_,
      WriteFile(base::FilePath("/sys/kernel/mm/chromeos-low_mem/margin"),
                kChromeosLowMemMargin8G))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(
      mock_util_,
      WriteFile(base::FilePath("/proc/sys/vm/min_filelist_kbytes"), "1000000"))
      .WillOnce(Return(absl::OkStatus()));
  // GetZramSize
  EXPECT_CALL(mock_util_, ReadFileToStringWithMaxSize(
                              base::FilePath("/var/lib/swap/swap_size"), _, _))
      .WillOnce(DoAll(SetArgPointee<1>("0"), Return(absl::OkStatus())));

  EXPECT_THAT(swap_tool_->SwapStart(), absl::OkStatus());
}

TEST_F(SwapToolTest, SwapStartWithEmptySwapZramSize) {
  // IsZramSwapOn
  EXPECT_CALL(mock_util_, ReadFileToString(base::FilePath("/proc/swaps"), _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kSwapsNoZram), Return(absl::OkStatus())));
  // GetMemTotal
  EXPECT_CALL(mock_util_, ReadFileToString(base::FilePath("/proc/meminfo"), _))
      .WillOnce(DoAll(SetArgPointee<1>(kMeminfoMemTotal8G),
                      Return(absl::OkStatus())));
  // InitializeMMTunables
  EXPECT_CALL(
      mock_util_,
      WriteFile(base::FilePath("/sys/kernel/mm/chromeos-low_mem/margin"),
                kChromeosLowMemMargin8G))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(
      mock_util_,
      WriteFile(base::FilePath("/proc/sys/vm/min_filelist_kbytes"), "1000000"))
      .WillOnce(Return(absl::OkStatus()));
  // GetZramSize
  EXPECT_CALL(mock_util_, ReadFileToStringWithMaxSize(
                              base::FilePath("/var/lib/swap/swap_size"), _, _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(absl::OkStatus())));
  EXPECT_CALL(mock_util_,
              RunProcessHelper(ElementsAre("/sbin/modprobe", "zram")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_, WriteFile(base::FilePath("/sys/block/zram0/disksize"),
                                    kZramDisksize8G))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_,
              RunProcessHelper(ElementsAre("/sbin/mkswap", "/dev/zram0")))
      .WillOnce(Return(absl::OkStatus()));
  // EnableZramSwapping
  EXPECT_CALL(mock_util_,
              RunProcessHelper(ElementsAre("/sbin/swapon", "/dev/zram0")))
      .WillOnce(Return(absl::OkStatus()));

  EXPECT_THAT(swap_tool_->SwapStart(), absl::OkStatus());
}

TEST_F(SwapToolTest, SwapStop) {
  // IsZramSwapOn
  EXPECT_CALL(mock_util_, ReadFileToString(base::FilePath("/proc/swaps"), _))
      .WillOnce(DoAll(
          SetArgPointee<1>(absl::StrCat(std::string(kSwapsNoZram),
                                        "/zram0                              "
                                        "partition       16288844        "
                                        "0               -2\n")),
          Return(absl::OkStatus())));
  EXPECT_CALL(mock_util_, RunProcessHelper(
                              ElementsAre("/sbin/swapoff", "-v", "/dev/zram0")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_, WriteFile(base::FilePath("/sys/block/zram0/reset"),
                                    std::to_string(1)))
      .WillOnce(Return(absl::OkStatus()));

  EXPECT_THAT(swap_tool_->SwapStop(), absl::OkStatus());
}

TEST_F(SwapToolTest, SwapSetSize) {
  // If size is negative.
  EXPECT_CALL(mock_util_, WriteFile(base::FilePath("/var/lib/swap/swap_size"),
                                    absl::StrCat(0)))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_THAT(swap_tool_->SwapSetSize(-1), absl::OkStatus());

  // If size is 0.
  EXPECT_CALL(mock_util_, DeleteFile(base::FilePath("/var/lib/swap/swap_size")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_THAT(swap_tool_->SwapSetSize(0), absl::OkStatus());

  // If size is larger than 65000.
  absl::Status status = swap_tool_->SwapSetSize(128000);
  EXPECT_TRUE(absl::IsInvalidArgument(status));
  EXPECT_EQ(status.ToString(),
            "INVALID_ARGUMENT: Size is not between 128 and 65000 MiB.");

  // If size is smaller than 128, but not 0.
  status = swap_tool_->SwapSetSize(64);
  EXPECT_TRUE(absl::IsInvalidArgument(status));
  EXPECT_EQ(status.ToString(),
            "INVALID_ARGUMENT: Size is not between 128 and 65000 MiB.");

  // If size is between 128 and 65000.
  EXPECT_CALL(mock_util_, WriteFile(base::FilePath("/var/lib/swap/swap_size"),
                                    absl::StrCat(1024)))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_THAT(swap_tool_->SwapSetSize(1024), absl::OkStatus());
}

TEST_F(SwapToolTest, SwapZramEnableWriteback) {
  // ZramWritebackPrerequisiteCheck
  EXPECT_CALL(
      mock_util_,
      ReadFileToString(base::FilePath("/sys/block/zram0/backing_dev"), _))
      .WillOnce(DoAll(SetArgPointee<1>("none\n"), Return(absl::OkStatus())));
  EXPECT_CALL(mock_util_, DeleteFile(base::FilePath("/run/zram-integrity")))
      .WillOnce(Return(absl::OkStatus()));

  // GetZramWritebackInfo
  struct statfs sf = {
      .f_bsize = 4096,
      .f_blocks = 2038647,
      .f_bfree = 1159962,
  };
  EXPECT_CALL(
      mock_util_,
      GetStatfs("/mnt/stateful_partition/unencrypted/userspace_swap.tmp"))
      .WillOnce(Return(std::move(sf)));

  // CreateDmDevicesAndEnableWriteback
  EXPECT_CALL(
      mock_util_,
      WriteFile(base::FilePath("/mnt/stateful_partition/unencrypted/"
                               "userspace_swap.tmp/zram_writeback.swap"),
                std::string()))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(
      mock_util_,
      Fallocate(base::FilePath("/mnt/stateful_partition/unencrypted/"
                               "userspace_swap.tmp/zram_writeback.swap"),
                134217728))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(
      mock_util_,
      RunProcessHelper(ElementsAre("/sbin/losetup", "--show", "--direct-io=on",
                                   "--sector-size=4096", "-f",
                                   "/mnt/stateful_partition/unencrypted/"
                                   "userspace_swap.tmp/zram_writeback.swap"),
                       _))
      .WillOnce(
          DoAll(SetArgPointee<1>("/dev/loop10\n"), Return(absl::OkStatus())));
  EXPECT_CALL(mock_util_,
              CreateDirectory(base::FilePath("/run/zram-integrity")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_, SetPosixFilePermissions(
                              base::FilePath("/run/zram-integrity"), 0700))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_, Mount("none", "/run/zram-integrity", "ramfs", 0,
                                "noexec,nosuid,noatime,mode=0700"))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(
      mock_util_,
      WriteFile(base::FilePath("/run/zram-integrity/zram_integrity.swap"),
                std::string(1048576, 0)))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(
      mock_util_,
      RunProcessHelper(ElementsAre("/sbin/losetup", "--show", "-f",
                                   "/run/zram-integrity/zram_integrity.swap"),
                       _))
      .WillOnce(
          DoAll(SetArgPointee<1>("/dev/loop11\n"), Return(absl::OkStatus())));

  EXPECT_CALL(
      mock_util_,
      RunProcessHelper(ElementsAre(
          "/sbin/dmsetup", "create", "zram-integrity", "--table",
          "0 262144 integrity /dev/loop10 0 24 D 4 block_size:4096 "
          "meta_device:/dev/loop11 journal_sectors:1 buffer_sectors:128")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_,
              PathExists(base::FilePath("/dev/mapper/zram-integrity")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_, GenerateRandHex(32))
      .WillOnce(Return(std::move(
          "31EDB364E004FA99CFDBA21D726284A810421F7466F892ED2306DB7FB917084E")));
  EXPECT_CALL(mock_util_,
              RunProcessHelper(ElementsAre(
                  "/sbin/dmsetup", "create", "zram-writeback", "--table",
                  "0 262144 crypt capi:gcm(aes)-random "
                  "31EDB364E004FA99CFDBA21D726284A810421F7466F892ED2306DB7FB917"
                  "084E 0 /dev/mapper/zram-integrity 0 4 allow_discards "
                  "submit_from_crypt_cpus sector_size:4096 integrity:24:aead")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_,
              PathExists(base::FilePath("/dev/mapper/zram-writeback")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_,
              WriteFile(base::FilePath("/sys/block/zram0/backing_dev"),
                        "/dev/mapper/zram-writeback"))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_, DeleteFile(base::FilePath(
                              "/mnt/stateful_partition/unencrypted/"
                              "userspace_swap.tmp/zram_writeback.swap")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(
      mock_util_,
      DeleteFile(base::FilePath("/run/zram-integrity/zram_integrity.swap")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_, RunProcessHelper(ElementsAre("/sbin/losetup", "-d",
                                                       "/dev/loop10")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_, RunProcessHelper(ElementsAre("/sbin/losetup", "-d",
                                                       "/dev/loop11")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_,
              RunProcessHelper(ElementsAre("/sbin/dmsetup", "remove",
                                           "--deferred", "zram-writeback")))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_util_,
              RunProcessHelper(ElementsAre("/sbin/dmsetup", "remove",
                                           "--deferred", "zram-integrity")))
      .WillOnce(Return(absl::OkStatus()));

  EXPECT_THAT(swap_tool_->SwapZramEnableWriteback(128), absl::OkStatus());
}

}  // namespace swap_management
