// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The kernel collector reports kernel panics or other kernel-level issues that
// caused machine reboot, like EFI crashes and BIOS crashes.
// The kernel collector runs on boot, via the crash-boot-collect service.

#ifndef CRASH_REPORTER_KERNEL_COLLECTOR_H_
#define CRASH_REPORTER_KERNEL_COLLECTOR_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash-reporter/crash_collector.h"
#include "crash-reporter/kernel_util.h"

// Kernel crash collector.
class KernelCollector : public CrashCollector {
 public:
  KernelCollector();
  KernelCollector(const KernelCollector&) = delete;
  KernelCollector& operator=(const KernelCollector&) = delete;

  ~KernelCollector() override;

  void OverrideEventLogPath(const base::FilePath& file_path);
  void OverrideBiosLogPath(const base::FilePath& file_path);
  void OverridePreservedDumpPath(const base::FilePath& file_path);
  void OverrideWatchdogSysPath(const base::FilePath& file_path);

  // Enable collection.
  bool Enable();

  // Returns true if the kernel collection currently enabled.
  bool is_enabled() const { return is_enabled_; }

  // Collect any preserved kernel crash dump. Returns true if there was
  // a dump (even if there were problems storing the dump), false otherwise.
  bool Collect(bool use_saved_lsb);

  // Set the architecture of the crash dumps we are looking at.
  void set_arch(kernel_util::ArchKind arch) { arch_ = arch; }
  kernel_util::ArchKind arch() const { return arch_; }

 protected:
  // This class represents single EFI crash.
  class EfiCrash {
   public:
    explicit EfiCrash(uint64_t id, const KernelCollector& collector)
        : id_(id),
          timestamp_(GetTimestamp(id)),
          max_part_(GetPart(id)),
          crash_count_(GetCrashCount(id)),
          collector_(collector) {}

    bool Load(std::string* contents) const;
    bool GetType(std::string* crash_type) const;
    void Remove() const;
    // Returns efi crash id.
    uint64_t GetId() const { return id_; }

    // Updates part from crash id iff it's greater.
    void UpdateMaxPart(uint64_t id) {
      uint32_t part = GetPart(id);
      if (part > max_part_) {
        max_part_ = part;
      }
    }

    constexpr uint64_t GetIdForPart(uint32_t part) const {
      return GenerateId(timestamp_, part, crash_count_);
    }

    // Helper functions for parsing and generating efi crash id.

    // Get efi crash id for given part.
    static constexpr uint64_t GetIdForPart(uint64_t id, uint32_t part) {
      return GenerateId(GetTimestamp(id), part, GetCrashCount(id));
    }
    // Get crash count from efi crash id.
    static constexpr uint32_t GetCrashCount(uint64_t id) {
      return id % kMaxDumpRecord;
    }

    // Get part number from efi crash id.
    static constexpr uint32_t GetPart(uint64_t id) {
      return (id / kMaxDumpRecord) % kMaxPart;
    }

    // Get timestamp from efi crash id.
    static constexpr uint64_t GetTimestamp(uint64_t id) {
      return (id / (kMaxDumpRecord * kMaxPart));
    }

    // Generates efi crash id from timestamp, part, crash count.
    // EFI File name is of format dmesg-efi-<crash_id>. Since one kernel crash
    // is split into multiple parts, <crash_id> is derived by
    // crash_id = (timestamp * 100 + part) * 1000 + crash_count.
    // See efi-pstore driver (https://goo.gl/1YBeCD) for more information.
    // e.g. File "dmesg-efi-150989600314002" represents part 14 of crash 2.
    static constexpr uint64_t GenerateId(uint64_t timestamp,
                                         uint32_t part,
                                         uint32_t crash_count) {
      return (timestamp * kMaxPart + part) * kMaxDumpRecord + crash_count;
    }

    static constexpr size_t kMaxDumpRecord = 1000;
    static constexpr size_t kMaxPart = 100;

   private:
    uint64_t id_;
    uint64_t timestamp_;
    uint32_t max_part_;
    uint32_t crash_count_;
    const KernelCollector& collector_;
    base::FilePath GetFilePath(uint32_t part) const;
  };

 private:
  friend class KernelCollectorTest;
  FRIEND_TEST(KernelCollectorTest, LoadPreservedDump);
  FRIEND_TEST(KernelCollectorTest, LoadBiosLog);
  FRIEND_TEST(KernelCollectorTest, CollectOK);
  FRIEND_TEST(KernelCollectorTest, ParseEfiCrashId);
  FRIEND_TEST(KernelCollectorTest, GetEfiCrashType);
  FRIEND_TEST(KernelCollectorTest, LoadEfiCrash);
  FRIEND_TEST(KernelCollectorTest, LastRebootWasNoCError);

  virtual bool DumpDirMounted();

  bool LoadPreservedDump(std::string* contents);
  bool LoadLastBootBiosLog(std::string* contents);

  bool LastRebootWasBiosCrash(const std::string& dump);
  bool LastRebootWasNoCError(const std::string& dump);
  bool LastRebootWasWatchdog(std::string& signature);
  bool LoadConsoleRamoops(std::string* contents);

  base::FilePath GetDumpRecordPath(const char* type,
                                   const char* driver,
                                   size_t record);
  base::FilePath GetDumpRecordOldPath(const char* type, const char* driver);

  bool LoadParameters();
  bool HasMoreRecords();

  // Read a record to string, modified from file_utils since that didn't
  // provide a way to restrict the read length.
  // Return value indicates (only) error state:
  //  * false when we get an error (can't read from dump location).
  //  * true if no error occured.
  // Not finding a valid record is not an error state and is signaled by the
  // record_found output parameter.
  bool ReadRecordToString(std::string* contents,
                          size_t current_record,
                          bool* record_found);

  void AddLogFile(const char* log_name,
                  const std::string& log_data,
                  const base::FilePath& log_path);

  bool HandleCrash(const std::string& kernel_dump,
                   const std::string& bios_dump,
                   const std::string& hypervisor_dump,
                   const std::string& signature);

  // Collects ramoops crash.
  bool CollectRamoopsCrash();

  // Collects efi crash.
  bool CollectEfiCrash();

  std::vector<EfiCrash> FindEfiCrashes() const;

  bool is_enabled_;
  base::FilePath eventlog_path_;
  base::FilePath dump_path_;
  base::FilePath bios_log_path_;
  base::FilePath watchdogsys_path_;
  size_t records_;

  // The architecture of kernel dump strings we are working with.
  kernel_util::ArchKind arch_;
};

#endif  // CRASH_REPORTER_KERNEL_COLLECTOR_H_
