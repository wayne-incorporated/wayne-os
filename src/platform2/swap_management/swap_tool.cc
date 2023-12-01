// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "swap_management/swap_tool.h"
#include "swap_management/swap_tool_status.h"

#include <cinttypes>
#include <utility>

#include <base/files/dir_reader_posix.h>
#include <base/logging.h>
#include <base/posix/safe_strerror.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <chromeos/dbus/swap_management/dbus-constants.h>

namespace swap_management {

namespace {

constexpr char kSwapSizeFile[] = "/var/lib/swap/swap_size";
constexpr char kZramDeviceFile[] = "/dev/zram0";
constexpr char kZramSysfsDir[] = "/sys/block/zram0";
constexpr char kZramWritebackName[] = "zram-writeback";
constexpr char kZramIntegrityName[] = "zram-integrity";
constexpr char kZramWritebackIntegrityMount[] = "/run/zram-integrity";
constexpr char kZramBackingDevice[] = "/sys/block/zram0/backing_dev";
constexpr char kStatefulPartitionDir[] =
    "/mnt/stateful_partition/unencrypted/userspace_swap.tmp";
constexpr uint32_t kMiB = 1048576;
constexpr uint32_t kSectorSize = 512;

constexpr base::TimeDelta kMaxIdleAge = base::Days(30);
constexpr uint64_t kMinFilelistDefaultValueKB = 1000000;

// Round up multiple will round the first argument |number| up to the next
// multiple of the second argument |alignment|.
uint64_t RoundupMultiple(uint64_t number, uint64_t alignment) {
  return ((number + (alignment - 1)) / alignment) * alignment;
}

}  // namespace

absl::StatusOr<std::unique_ptr<LoopDev>> LoopDev::Create(
    const std::string& path) {
  return Create(path, false, 0);
}

absl::StatusOr<std::unique_ptr<LoopDev>> LoopDev::Create(
    const std::string& path, bool direct_io, uint32_t sector_size) {
  std::vector<std::string> command({"/sbin/losetup", "--show"});
  if (direct_io)
    command.push_back("--direct-io=on");
  if (sector_size != 0)
    command.push_back("--sector-size=" + std::to_string(sector_size));
  command.push_back("-f");
  command.push_back(path);

  std::string loop_dev_path;
  absl::Status status =
      SwapToolUtil::Get()->RunProcessHelper(command, &loop_dev_path);
  if (!status.ok())
    return status;
  base::TrimWhitespaceASCII(loop_dev_path, base::TRIM_ALL, &loop_dev_path);

  return std::unique_ptr<LoopDev>(new LoopDev(loop_dev_path));
}

LoopDev::~LoopDev() {
  absl::Status status = absl::OkStatus();

  if (!path_.empty()) {
    status =
        SwapToolUtil::Get()->RunProcessHelper({"/sbin/losetup", "-d", path_});
    LOG_IF(ERROR, !status.ok()) << status;
    path_.clear();
  }
}

std::string LoopDev::GetPath() {
  return path_;
}

absl::StatusOr<std::unique_ptr<DmDev>> DmDev::Create(
    const std::string& name, const std::string& table_fmt) {
  absl::Status status = absl::OkStatus();

  status = SwapToolUtil::Get()->RunProcessHelper(
      {"/sbin/dmsetup", "create", name, "--table", table_fmt});
  if (!status.ok())
    return status;

  std::unique_ptr<DmDev> dm_dev = std::unique_ptr<DmDev>(new DmDev(name));

  status = dm_dev->Wait();
  if (!status.ok())
    return status;

  return std::move(dm_dev);
}

DmDev::~DmDev() {
  absl::Status status = absl::OkStatus();

  if (!name_.empty()) {
    status = SwapToolUtil::Get()->RunProcessHelper(
        {"/sbin/dmsetup", "remove", "--deferred", name_});
    LOG_IF(ERROR, !status.ok()) << status;
    name_.clear();
  }
}

// Wait for up to 5 seconds for a dm device to become available,
// if it doesn't then return failed status. This is needed because dm devices
// may take a few seconds to become visible at /dev/mapper after the table is
// switched.
absl::Status DmDev::Wait() {
  constexpr base::TimeDelta kMaxWaitTime = base::Seconds(5);
  constexpr base::TimeDelta kRetryDelay = base::Milliseconds(100);
  std::string path = GetPath();

  base::Time startTime = base::Time::Now();
  while (true) {
    if (base::Time::Now() - startTime > kMaxWaitTime)
      return absl::UnavailableError(
          path + " is not available after " +
          std::to_string(kMaxWaitTime.InMilliseconds()) + " ms.");

    if (SwapToolUtil::Get()
            ->PathExists(base::FilePath("/dev/mapper/").Append(name_))
            .ok())
      return absl::OkStatus();

    base::PlatformThread::Sleep(kRetryDelay);
  }
}

std::string DmDev::GetPath() {
  return "/dev/mapper/" + name_;
}

// Check if swap is already turned on.
absl::StatusOr<bool> SwapTool::IsZramSwapOn() {
  std::string swaps;
  absl::Status status = SwapToolUtil::Get()->ReadFileToString(
      base::FilePath("/proc/swaps"), &swaps);
  if (!status.ok())
    return status;

  std::vector<std::string> swaps_lines = base::SplitString(
      swaps, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  // Skip the first line which is header. Swap is turned on if swaps_lines
  // contains entry with zram0 keyword.
  for (size_t i = 1; i < swaps_lines.size(); i++) {
    if (swaps_lines[i].find("zram0") != std::string::npos)
      return true;
  }

  return false;
}

// Extract second field of MemTotal entry in /proc/meminfo. The unit for
// MemTotal is KiB.
absl::StatusOr<uint64_t> SwapTool::GetMemTotal() {
  std::string mem_info;
  absl::Status status = SwapToolUtil::Get()->ReadFileToString(
      base::FilePath("/proc/meminfo"), &mem_info);
  if (!status.ok())
    return status;

  std::vector<std::string> mem_info_lines = base::SplitString(
      mem_info, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  for (auto& line : mem_info_lines) {
    if (line.find("MemTotal") != std::string::npos) {
      std::string buf = base::SplitString(line, " ", base::KEEP_WHITESPACE,
                                          base::SPLIT_WANT_NONEMPTY)[1];

      uint64_t res = 0;
      if (!absl::SimpleAtoi(buf, &res))
        return absl::OutOfRangeError("Failed to convert " + buf +
                                     " to 64-bit unsigned integer.");
      return res;
    }
  }

  return absl::NotFoundError("Could not get MemTotal in /proc/meminfo");
}

// Compute fraction of total RAM used for low-mem margin. The fraction is
// given in bips. A "bip" or "basis point" is 1/100 of 1%.
absl::Status SwapTool::SetDefaultLowMemoryMargin(uint64_t mem_total) {
  // Calculate critical margin in MiB, which is 5.2% free. Ignore the decimal.
  uint64_t critical_margin = (mem_total / 1024) * 0.052;
  // Calculate moderate margin in MiB, which is 40% free. Ignore the decimal.
  uint64_t moderate_margin = (mem_total / 1024) * 0.4;
  // Write into margin special file.
  return SwapToolUtil::Get()->WriteFile(
      base::FilePath("/sys/kernel/mm/chromeos-low_mem/margin"),
      std::to_string(critical_margin) + " " + std::to_string(moderate_margin));
}

// Initialize MM tunnables.
absl::Status SwapTool::InitializeMMTunables(uint64_t mem_total) {
  absl::Status status = SetDefaultLowMemoryMargin(mem_total);
  if (!status.ok())
    return status;

  return SwapToolUtil::Get()->WriteFile(
      base::FilePath("/proc/sys/vm/min_filelist_kbytes"),
      std::to_string(kMinFilelistDefaultValueKB));
}

// Return zram (compressed ram disk) size in byte for swap.
// kSwapSizeFile contains the zram size in MiB.
// Empty or missing kSwapSizeFile means use default size, which is
// mem_total
// * 2.
// 0 means do not enable zram.
absl::StatusOr<uint64_t> SwapTool::GetZramSize(uint64_t mem_total) {
  // For security, only read first few bytes of kSwapSizeFile.
  std::string buf;
  absl::Status status = SwapToolUtil::Get()->ReadFileToStringWithMaxSize(
      base::FilePath(kSwapSizeFile), &buf, 5);
  // If the file doesn't exist we use default zram size, other errors we must
  // propagate back.
  if (!status.ok() && !absl::IsNotFound(status))
    return status;

  // Trim the potential leading/trailing ASCII whitespaces.
  // Note that TrimWhitespaceASCII can safely use the same variable for inputs
  // and outputs.
  base::TrimWhitespaceASCII(buf, base::TRIM_ALL, &buf);

  if (absl::IsNotFound(status) || buf.empty())
    return mem_total * 1024 * 2;

  uint64_t requested_size_mib = 0;
  if (!absl::SimpleAtoi(buf, &requested_size_mib))
    return absl::OutOfRangeError("Failed to convert " +
                                 std::to_string(requested_size_mib) +
                                 " to 64-bit unsigned integer.");

  if (requested_size_mib == 0)
    LOG(WARNING) << "swap is disabled since " << std::string(kSwapSizeFile)
                 << " contains 0.";

  return requested_size_mib * 1024 * 1024;
}

// Run swapon to enable zram swapping.
// swapon may fail because of races with other programs that inspect all
// block devices, so try several times.
absl::Status SwapTool::EnableZramSwapping() {
  constexpr uint8_t kMaxEnableTries = 10;
  constexpr base::TimeDelta kRetryDelayUs = base::Milliseconds(100);
  absl::Status status = absl::OkStatus();

  for (size_t i = 0; i < kMaxEnableTries; i++) {
    status = SwapToolUtil::Get()->RunProcessHelper(
        {"/sbin/swapon", kZramDeviceFile});
    if (status.ok())
      return status;

    LOG(WARNING) << "swapon " << kZramDeviceFile << " failed, try " << i
                 << " times, last error:" << status;

    base::PlatformThread::Sleep(kRetryDelayUs);
  }

  return absl::AbortedError("swapon " + std::string(kZramDeviceFile) +
                            " failed after " + std::to_string(kMaxEnableTries) +
                            " tries" + " last error: " + status.ToString());
}

// If we're unable to setup writeback just make sure we clean up any
// mounts.
// Devices are cleanup while class instances are released.
// Errors happenes during cleanup will be logged.
void SwapTool::CleanupWriteback() {
  absl::Status status = absl::OkStatus();

  status = SwapToolUtil::Get()->Umount(kZramWritebackIntegrityMount);
  LOG_IF(ERROR, !status.ok()) << status;

  status = SwapToolUtil::Get()->DeleteFile(
      base::FilePath(kZramWritebackIntegrityMount));
  LOG_IF(ERROR, !status.ok()) << status;
}

// Check if zram writeback can be used on the system.
absl::Status SwapTool::ZramWritebackPrerequisiteCheck(uint32_t size) {
  absl::Status status = absl::OkStatus();

  // Don't allow |size| less than 128MiB or more than 6GiB to be configured.
  constexpr uint32_t kZramWritebackMinSize = 128;
  constexpr uint32_t kZramWritebackMaxSize = 6144;
  if (size < kZramWritebackMinSize || size > kZramWritebackMaxSize)
    return absl::InvalidArgumentError("Invalid size specified.");

  // kZramBackingDevice must contains none, no writeback is setup before.
  std::string backing_dev;
  status = SwapToolUtil::Get()->ReadFileToString(
      base::FilePath(kZramBackingDevice), &backing_dev);
  if (!status.ok())
    return status;
  base::TrimWhitespaceASCII(backing_dev, base::TRIM_ALL, &backing_dev);
  if (backing_dev != "none")
    return absl::AlreadyExistsError(
        "Zram already has a backing device assigned.");

  // kZramWritebackIntegrityMount must not be mounted.
  // rmdir(2) will return -EBUSY if the target is mounted.
  // DeleteFile returns absl::OkStatus() if the target does not exist.
  status = SwapToolUtil::Get()->DeleteFile(
      base::FilePath(kZramWritebackIntegrityMount));

  return status;
}

absl::Status SwapTool::GetZramWritebackInfo(uint32_t size) {
  absl::Status status = absl::OkStatus();

  // Read stateful partition file system statistics using statfs.
  // f_blocks is total data blocks in file system.
  // f_bfree is free blocks in file system.
  // f_bsize is the optimal transfer block size.
  absl::StatusOr<struct statfs> stateful_statfs =
      SwapToolUtil::Get()->GetStatfs(kStatefulPartitionDir);
  if (!stateful_statfs.ok())
    return stateful_statfs.status();

  // Never allow swapping to disk when the overall free diskspace is less
  // than 15% of the overall capacity.
  constexpr int kMinFreeStatefulPct = 15;
  uint64_t stateful_free_pct =
      100 * (*stateful_statfs).f_bfree / (*stateful_statfs).f_blocks;
  if (stateful_free_pct < kMinFreeStatefulPct)
    return absl::ResourceExhaustedError(
        "zram writeback cannot be enabled free disk space" +
        std::to_string(stateful_free_pct) + "% is less than the minimum 15%");

  stateful_block_size_ = (*stateful_statfs).f_bsize;
  wb_nr_blocks_ = size * kMiB / stateful_block_size_;
  uint64_t wb_pct_of_stateful =
      wb_nr_blocks_ * 100 / (*stateful_statfs).f_bfree;

  // Only allow 15% of the free diskspace for swap writeback by maximum.
  if (wb_pct_of_stateful > kMinFreeStatefulPct) {
    uint64_t old_size = size;
    wb_nr_blocks_ = kMinFreeStatefulPct * (*stateful_statfs).f_bfree / 100;
    size = wb_nr_blocks_ * stateful_block_size_ / kMiB;
    LOG(WARNING) << "zram writeback, requested size of " << old_size << " is "
                 << wb_pct_of_stateful
                 << "% of the free disk space. Size will be reduced to " << size
                 << "MiB";
  }

  wb_size_bytes_ = RoundupMultiple(size * kMiB, stateful_block_size_);
  // Because we rounded up writeback_size bytes recalculate the number of blocks
  // used.
  wb_nr_blocks_ = wb_size_bytes_ / stateful_block_size_;

  return absl::OkStatus();
}

absl::Status SwapTool::CreateDmDevicesAndEnableWriteback() {
  absl::Status status = absl::OkStatus();

  // Create the actual writeback space on the stateful partition.
  constexpr char kZramWritebackBackFileName[] = "zram_writeback.swap";
  ScopedFilePath scoped_filepath(
      base::FilePath(kStatefulPartitionDir).Append(kZramWritebackBackFileName));
  status = SwapToolUtil::Get()->WriteFile(scoped_filepath.get(), std::string());
  if (!status.ok())
    return status;
  status =
      SwapToolUtil::Get()->Fallocate(scoped_filepath.get(), wb_size_bytes_);
  if (!status.ok())
    return status;

  // Create writeback loop device.
  // See drivers/block/loop.c:230
  // We support direct I/O only if lo_offset is aligned with the
  // logical I/O size of backing device, and the logical block
  // size of loop is bigger than the backing device's and the loop
  // needn't transform transfer.
  auto writeback_loop = LoopDev::Create(scoped_filepath.get().value(), true,
                                        stateful_block_size_);
  if (!writeback_loop.ok())
    return writeback_loop.status();
  std::string writeback_loop_path = (*writeback_loop)->GetPath();

  // Create and mount ramfs for integrity loop device back file.
  status = SwapToolUtil::Get()->CreateDirectory(
      base::FilePath(kZramWritebackIntegrityMount));
  if (!status.ok())
    return status;
  status = SwapToolUtil::Get()->SetPosixFilePermissions(
      base::FilePath(kZramWritebackIntegrityMount), 0700);
  if (!status.ok())
    return status;
  status =
      SwapToolUtil::Get()->Mount("none", kZramWritebackIntegrityMount, "ramfs",
                                 0, "noexec,nosuid,noatime,mode=0700");
  if (!status.ok())
    return status;

  // Create integrity loop device.
  // See drivers/md/dm-integrity.c and
  // https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html
  // In direct write mode, The size of dm-integrity is data(tag) area + initial
  // segment.
  // The size of data(tag) area is (number of blocks in wb device) *
  // (tag size), and then roundup with the size of dm-integrity buffer. The
  // default number of sector in a dm-integrity buffer is 128 so the size is
  // 65536 bytes.
  // The size of initial segment is (superblock size == 4KB) + (size of
  // journal). dm-integrity requires at least one journal section even with
  // direct write mode. As for now, the size of a single journal section is
  // 167936 bytes (328 sectors)

  // AES-GCM uses a fixed 12 byte IV. The other 12 bytes are auth tag.
  constexpr size_t kDmIntegrityTagSize = 24;
  constexpr size_t kDmIntegrityBufSize = 65536;
  constexpr size_t kJournalSectionSize = kSectorSize * 328;
  constexpr size_t kSuperblockSize = 4096;
  constexpr size_t kInitialSegmentSize = kSuperblockSize + kJournalSectionSize;

  size_t data_area_size =
      RoundupMultiple(wb_nr_blocks_ * kDmIntegrityTagSize, kDmIntegrityBufSize);

  size_t integrity_size_bytes = data_area_size + kInitialSegmentSize;
  // To be safe, in case the size of dm-integrity increases in the future
  // development, roundup it with MiB.
  integrity_size_bytes = RoundupMultiple(integrity_size_bytes, kMiB);

  constexpr char kZramIntegrityBackFileName[] = "zram_integrity.swap";
  scoped_filepath = ScopedFilePath(base::FilePath(kZramWritebackIntegrityMount)
                                       .Append(kZramIntegrityBackFileName));
  // Truncate the file to the length of |integrity_size_bytes| by filling with
  // 0s.
  status = SwapToolUtil::Get()->WriteFile(scoped_filepath.get(),
                                          std::string(integrity_size_bytes, 0));
  if (!status.ok())
    return status;

  auto integrity_loop = LoopDev::Create(scoped_filepath.get().value());
  if (!integrity_loop.ok())
    return integrity_loop.status();
  std::string integrity_loop_path = (*integrity_loop)->GetPath();

  // Create a dm-integrity device to use with dm-crypt.
  // For the table format, refer to
  // https://wiki.gentoo.org/wiki/Device-mapper#Integrity
  std::string table_fmt = base::StringPrintf(
      "0 %" PRId64 " integrity %s 0 %zu D 4 block_size:%" PRId64
      " meta_device:%s journal_sectors:1 buffer_sectors:%zu",
      wb_size_bytes_ / kSectorSize, writeback_loop_path.c_str(),
      kDmIntegrityTagSize, stateful_block_size_, integrity_loop_path.c_str(),
      kDmIntegrityBufSize / kSectorSize);
  auto integrity_dm = DmDev::Create(kZramIntegrityName, table_fmt);
  if (!integrity_dm.ok())
    return integrity_dm.status();

  // Create a dm-crypt device for writeback.
  absl::StatusOr<std::string> rand_hex32 =
      SwapToolUtil::Get()->GenerateRandHex(32);
  if (!rand_hex32.ok())
    return rand_hex32.status();

  table_fmt = base::StringPrintf(
      "0 %" PRId64
      " crypt capi:gcm(aes)-random %s 0 /dev/mapper/%s 0 4 allow_discards "
      "submit_from_crypt_cpus sector_size:%" PRId64 " integrity:%zu:aead",
      wb_size_bytes_ / kSectorSize, (*rand_hex32).c_str(), kZramIntegrityName,
      stateful_block_size_, kDmIntegrityTagSize);

  auto writeback_dm = DmDev::Create(kZramWritebackName, table_fmt);
  if (!writeback_dm.ok())
    return writeback_dm.status();

  // Set up dm-crypt device as the zram writeback backing device.
  return SwapToolUtil::Get()->WriteFile(base::FilePath(kZramBackingDevice),
                                        (*writeback_dm)->GetPath());
}

absl::Status SwapTool::SwapStart() {
  absl::Status status = absl::OkStatus();

  // Return true if swap is already on.
  absl::StatusOr<bool> on = IsZramSwapOn();
  if (!on.ok())
    return on.status();
  if (*on) {
    LOG(WARNING) << "swap is already on.";
    return absl::OkStatus();
  }

  absl::StatusOr<uint64_t> mem_total = GetMemTotal();
  if (!mem_total.ok())
    return mem_total.status();

  status = InitializeMMTunables(*mem_total);
  if (!status.ok())
    return status;

  absl::StatusOr<uint64_t> size_byte = GetZramSize(*mem_total);
  if (!size_byte.ok() || *size_byte == 0)
    return size_byte.status();

  // Load zram module. Ignore failure (it could be compiled in the kernel).
  if (!SwapToolUtil::Get()->RunProcessHelper({"/sbin/modprobe", "zram"}).ok())
    LOG(WARNING) << "modprobe zram failed (compiled?)";

  // Set zram disksize.
  LOG(INFO) << "setting zram size to " << *size_byte << " bytes";
  status = SwapToolUtil::Get()->WriteFile(
      base::FilePath("/sys/block/zram0/disksize"), std::to_string(*size_byte));
  if (!status.ok())
    return status;

  // Set swap area.
  status =
      SwapToolUtil::Get()->RunProcessHelper({"/sbin/mkswap", kZramDeviceFile});
  if (!status.ok())
    return status;

  return EnableZramSwapping();
}

absl::Status SwapTool::SwapStop() {
  // Return false if swap is already off.
  absl::StatusOr<bool> on = IsZramSwapOn();
  if (!on.ok())
    return on.status();
  if (!*on) {
    LOG(WARNING) << "Swap is already off.";
    return absl::OkStatus();
  }

  // It is possible that the Filename of swap file zram0 in /proc/swaps shows
  // wrong path "/zram0", since devtmpfs in minijail mount namespace is lazily
  // unmounted while swap_management terminates.
  // At this point we already know swap is on, with the only swap device
  // /dev/zram0 we have, anyway we turn off /dev/zram0, regardless what
  // /proc/swaps shows.
  absl::Status status = SwapToolUtil::Get()->RunProcessHelper(
      {"/sbin/swapoff", "-v", kZramDeviceFile});
  if (!status.ok())
    return status;

  // When we start up, we try to configure zram0, but it doesn't like to
  // be reconfigured on the fly.  Reset it so we can changes its params.
  // If there was a backing device being used, it will be automatically
  // removed because after it's created it was removed with deferred remove.
  return SwapToolUtil::Get()->WriteFile(
      base::FilePath("/sys/block/zram0/reset"), "1");
}

// Set zram disksize in MiB.
// If `size` equals 0, set zram size file to the default value.
// If `size` is negative, set zram size file to 0. Swap is disabled if zram size
// file contains 0.
absl::Status SwapTool::SwapSetSize(int32_t size) {
  // Remove kSwapSizeFile so SwapStart will use default size for zram.
  if (size == 0) {
    return SwapToolUtil::Get()->DeleteFile(base::FilePath(kSwapSizeFile));
  } else if (size < 0) {
    size = 0;
  } else if (size < 128 || size > 65000) {
    return absl::InvalidArgumentError("Size is not between 128 and 65000 MiB.");
  }

  return SwapToolUtil::Get()->WriteFile(base::FilePath(kSwapSizeFile),
                                        std::to_string(size));
}

absl::Status SwapTool::SwapSetSwappiness(uint32_t swappiness) {
  // Only allow swappiness between 0 and 100.
  if (swappiness > 100)
    return absl::OutOfRangeError("Invalid swappiness " +
                                 std::to_string(swappiness));

  return SwapToolUtil::Get()->WriteFile(
      base::FilePath("/proc/sys/vm/swappiness"), std::to_string(swappiness));
}

std::string SwapTool::SwapStatus() {
  std::stringstream output;
  std::string tmp;

  // Show general swap info first.
  if (SwapToolUtil::Get()
          ->ReadFileToString(base::FilePath("/proc/swaps"), &tmp)
          .ok())
    output << tmp;

  // Show tunables.
  if (SwapToolUtil::Get()
          ->ReadFileToString(
              base::FilePath("/sys/kernel/mm/chromeos-low_mem/margin"), &tmp)
          .ok())
    output << "low-memory margin (MiB): " + tmp;
  if (SwapToolUtil::Get()
          ->ReadFileToString(base::FilePath("/proc/sys/vm/min_filelist_kbytes"),
                             &tmp)
          .ok())
    output << "min_filelist_kbytes (KiB): " + tmp;
  if (SwapToolUtil::Get()
          ->ReadFileToString(
              base::FilePath(
                  "/sys/kernel/mm/chromeos-low_mem/ram_vs_swap_weight"),
              &tmp)
          .ok())
    output << "ram_vs_swap_weight: " + tmp;
  if (SwapToolUtil::Get()
          ->ReadFileToString(base::FilePath("/proc/sys/vm/extra_free_kbytes"),
                             &tmp)
          .ok())
    output << "extra_free_kbytes (KiB): " + tmp;

  // Show top entries in kZramSysfsDir for zram setting.
  base::DirReaderPosix dir_reader(kZramSysfsDir);
  if (dir_reader.IsValid()) {
    output << "\ntop-level entries in " + std::string(kZramSysfsDir) + ":\n";

    base::FilePath zram_sysfs(kZramSysfsDir);
    while (dir_reader.Next()) {
      std::string name = dir_reader.name();

      if (SwapToolUtil::Get()
              ->ReadFileToString(zram_sysfs.Append(name), &tmp)
              .ok() &&
          !tmp.empty()) {
        std::vector<std::string> lines = base::SplitString(
            tmp, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
        for (auto& line : lines)
          output << name + ": " + line + "\n";
      }
    }
  }

  return output.str();
}

absl::Status SwapTool::SwapZramEnableWriteback(uint32_t size) {
  absl::Status status = absl::OkStatus();

  status = ZramWritebackPrerequisiteCheck(size);
  if (!status.ok())
    return status;

  status = GetZramWritebackInfo(size);
  if (!status.ok())
    return status;

  status = CreateDmDevicesAndEnableWriteback();
  if (!status.ok()) {
    CleanupWriteback();
    return status;
  }

  LOG(INFO) << "Enabled writeback with size " +
                   std::to_string(wb_size_bytes_ / kMiB) + "MiB";

  return absl::OkStatus();
}

absl::Status SwapTool::SwapZramSetWritebackLimit(uint32_t num_pages) {
  base::FilePath filepath =
      base::FilePath(kZramSysfsDir).Append("writeback_limit_enable");

  absl::Status status = SwapToolUtil::Get()->WriteFile(filepath, "1");
  if (!status.ok())
    return status;

  filepath = base::FilePath(kZramSysfsDir).Append("writeback_limit");

  return SwapToolUtil::Get()->WriteFile(filepath, std::to_string(num_pages));
}

absl::Status SwapTool::SwapZramMarkIdle(uint32_t age_seconds) {
  const auto age = base::Seconds(age_seconds);

  // Only allow marking pages as idle between 0 sec and 30 days.
  if (age > kMaxIdleAge)
    return absl::OutOfRangeError("Invalid age " + std::to_string(age_seconds));

  base::FilePath filepath = base::FilePath(kZramSysfsDir).Append("idle");
  return SwapToolUtil::Get()->WriteFile(filepath,
                                        std::to_string(age.InSeconds()));
}

absl::Status SwapTool::InitiateSwapZramWriteback(uint32_t mode) {
  base::FilePath filepath = base::FilePath(kZramSysfsDir).Append("writeback");
  std::string mode_str;
  if (mode == WRITEBACK_IDLE) {
    mode_str = "idle";
  } else if (mode == WRITEBACK_HUGE) {
    mode_str = "huge";
  } else if (mode == WRITEBACK_HUGE_IDLE) {
    mode_str = "huge_idle";
  } else {
    return absl::InvalidArgumentError("Invalid mode");
  }

  return SwapToolUtil::Get()->WriteFile(filepath, mode_str);
}

absl::Status SwapTool::MGLRUSetEnable(uint8_t value) {
  return SwapToolUtil::Get()->WriteFile(
      base::FilePath("/sys/kernel/mm/lru_gen/enabled"), std::to_string(value));
}

}  // namespace swap_management
