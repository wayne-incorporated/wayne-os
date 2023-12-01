// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/kernel_collector.h"

#include <algorithm>
#include <cinttypes>
#include <utility>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <linux/watchdog.h>
#include <re2/re2.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

using base::FilePath;
using base::StringPiece;
using base::StringPrintf;

namespace {

// Name for extra BIOS dump attached to report. Also used as metadata key.
constexpr char kBiosDumpName[] = "bios_log";
constexpr char kHypervisorDumpName[] = "hypervisor_log";
const FilePath kBiosLogPath("/sys/firmware/log");
// Names of the four BIOS stages in which the BIOS log can start.
const char* const kBiosStageNames[] = {
    "bootblock",
    "verstage",
    "romstage",
    "ramstage",
};
constexpr char kDumpParentPath[] = "/sys/fs";
constexpr char kDumpPath[] = "/sys/fs/pstore";
constexpr char kDumpRecordDmesgName[] = "dmesg";
constexpr char kDumpRecordConsoleName[] = "console";
constexpr char kDumpDriverRamoopsName[] = "ramoops";
constexpr char kDumpDriverEfiName[] = "efi";
// The files take the form <record type>-<driver name>-<record id>.
// e.g. console-ramoops-0 or dmesg-ramoops-0.
constexpr char kDumpNameFormat[] = "%s-%s-%zu";
// Like above, but for older systems when the kernel didn't add the record id.
constexpr char kDumpNameFormatOld[] = "%s-%s";

const FilePath kEventLogPath("/var/log/eventlog.txt");
constexpr char kEventNameBoot[] = "System boot";
constexpr char kEventNameWatchdog[] = "Hardware watchdog reset";
// Maximum number of records to examine in the kDumpPath.
constexpr size_t kMaxDumpRecords = 100;
// Maximum buffer size of pstore records reads. PSTORE_DEFAULT_KMSG_BYTES as set
// in the kernel is 10KiB, and record_size for RAM Oops/Panic trigger is
// defaulted at 4KiB with another 4KiB each for console, ftrace, and pmsg logs.
// This gives a maximum of ~26 KiB, but in practice logs can be significantly
// larger (e.g. 66 KiB is easily achieved). Set a limit substantially above
// this.
constexpr size_t kMaxRecordSize = 1024 * 1024;
constexpr pid_t kKernelPid = 0;
constexpr char kKernelSignatureKey[] = "sig";

// Used to build up the path to a watchdog's boot status:
// For example: /sys/class/watchdog/watchdog0/bootstatus
constexpr char kWatchdogSysBootstatusFile[] = "bootstatus";

static LazyRE2 kBasicCheckRe = {"\n(<\\d+>)?\\[\\s*(\\d+\\.\\d+)\\]"};

}  // namespace

KernelCollector::KernelCollector()
    : CrashCollector("kernel"),
      is_enabled_(false),
      eventlog_path_(kEventLogPath),
      dump_path_(kDumpPath),
      bios_log_path_(kBiosLogPath),
      watchdogsys_path_(paths::Get(paths::kWatchdogSysPath)),
      records_(0),
      // We expect crash dumps in the format of architecture we are built for.
      arch_(kernel_util::GetCompilerArch()) {}

KernelCollector::~KernelCollector() {}

void KernelCollector::OverrideEventLogPath(const FilePath& file_path) {
  eventlog_path_ = file_path;
}

void KernelCollector::OverrideBiosLogPath(const FilePath& file_path) {
  bios_log_path_ = file_path;
}

void KernelCollector::OverridePreservedDumpPath(const FilePath& file_path) {
  dump_path_ = file_path;
}

void KernelCollector::OverrideWatchdogSysPath(const FilePath& file_path) {
  watchdogsys_path_ = file_path;
}

bool KernelCollector::ReadRecordToString(std::string* contents,
                                         size_t current_record,
                                         bool* record_found) {
  // A record is a ramoops dump. It has an associated size of "record_size".
  std::string record;
  std::string captured;

  // Ramoops appends a header to a crash which contains ==== followed by a
  // timestamp. Ignore the header.
  RE2::Options opt;
  opt.set_dot_nl(true);  // match \n with '.'
  RE2 record_re("====\\d+\\.\\d+\n(.*)", opt);

  FilePath record_path = GetDumpRecordPath(
      kDumpRecordDmesgName, kDumpDriverRamoopsName, current_record);
  if (!base::ReadFileToStringWithMaxSize(record_path, &record,
                                         kMaxRecordSize)) {
    if (record.empty()) {
      PLOG(ERROR) << "Unable to read " << record_path.value();
      return false;
    }

    PLOG(ERROR) << "Record is larger than " << kMaxRecordSize;
    return false;
  }

  *record_found = false;
  if (RE2::FullMatch(record, record_re, &captured)) {
    // Found a ramoops header, so strip the header and append the rest.
    contents->append(captured);
    *record_found = true;
  } else if (RE2::PartialMatch(record.substr(0, 1024), *kBasicCheckRe)) {
    // pstore compression has been added since kernel 3.12. In order to
    // decompress dmesg correctly, ramoops driver has to strip the header
    // before handing over the record to the pstore driver, so we don't
    // need to do it here anymore. However, the basic check is needed because
    // sometimes a pstore record is just a chunk of uninitialized memory which
    // is not the result of a kernel crash. See crbug.com/443764
    contents->append(record);
    *record_found = true;
  } else {
    LOG(WARNING) << "Found invalid record at " << record_path.value();
  }

  // Remove the record from pstore after it's found.
  if (*record_found)
    base::DeleteFile(record_path);

  return true;
}

FilePath KernelCollector::GetDumpRecordPath(const char* type,
                                            const char* driver,
                                            size_t record) {
  return dump_path_.Append(StringPrintf(kDumpNameFormat, type, driver, record));
}

FilePath KernelCollector::GetDumpRecordOldPath(const char* type,
                                               const char* driver) {
  return dump_path_.Append(StringPrintf(kDumpNameFormatOld, type, driver));
}

bool KernelCollector::LoadParameters() {
  // Discover how many ramoops records are being exported by the driver.
  size_t count;

  for (count = 0; count < kMaxDumpRecords; ++count) {
    FilePath record_path =
        GetDumpRecordPath(kDumpRecordDmesgName, kDumpDriverRamoopsName, count);

    if (!base::PathExists(record_path))
      break;
  }

  records_ = count;
  return (records_ > 0);
}

bool KernelCollector::LoadPreservedDump(std::string* contents) {
  // Load dumps from the preserved memory and save them in contents.
  // Since the system is set to restart on oops we won't actually ever have
  // multiple records (only 0 or 1), but check in case we don't restart on
  // oops in the future.
  bool any_records_found = false;
  bool record_found = false;
  // clear contents since ReadFileToString actually appends to the string.
  contents->clear();

  for (size_t i = 0; i < records_; ++i) {
    if (!ReadRecordToString(contents, i, &record_found)) {
      break;
    }
    if (record_found) {
      any_records_found = true;
    }
  }

  if (!any_records_found) {
    LOG(ERROR) << "No valid records found in " << dump_path_.value();
    return false;
  }

  return true;
}

bool KernelCollector::LoadLastBootBiosLog(std::string* contents) {
  contents->clear();

  if (!base::PathExists(bios_log_path_)) {
    LOG(INFO) << bios_log_path_.value() << " does not exist, skipping "
              << "BIOS crash check. (This is normal for older boards.)";
    return false;
  }

  std::string full_log;
  if (!base::ReadFileToString(bios_log_path_, &full_log)) {
    PLOG(ERROR) << "Unable to read " << bios_log_path_.value();
    return false;
  }

  RE2::Options opt;
  opt.set_dot_nl(true);  // match \n with '.'
  // Different platforms start their BIOS log at different stages. Look for
  // banner strings of all stages in order until we find one that works.
  for (auto stage : kBiosStageNames) {
    // use the "^" to anchor to the start of the string
    RE2 banner_re(StringPrintf("(^.*?)(?:"
                               "\n\\*\\*\\* Pre-CBMEM %s console overflow"
                               "|\n\n[^\n]*"
                               "coreboot-[^\n]* %s starting.*\\.\\.\\.\n"
                               ")",
                               stage, stage),
                  opt);
    re2::StringPiece remaining_log(full_log);
    re2::StringPiece previous_boot;
    bool found = false;

    // Keep iterating until last previous_boot before current one.
    while (RE2::PartialMatch(remaining_log, banner_re, &previous_boot)) {
      remaining_log.remove_prefix(previous_boot.size() + 1);
      found = true;
    }

    if (!previous_boot.empty()) {
      previous_boot.CopyToString(contents);
      return true;
    }

    // If banner found but no log before it, don't look for other stage banners.
    // This just means we booted up from S5 and there was nothing left in DRAM.
    if (found)
      return false;
  }

  // This shouldn't happen since we should always see at least the current boot.
  LOG(ERROR) << "BIOS log contains no known banner strings!";
  return false;
}

bool KernelCollector::LastRebootWasBiosCrash(const std::string& dump) {
  // BIOS crash detection only supported on ARM64 for now. We're in userspace,
  // so we can't easily check for 64-bit (but that's not a big deal).
  if (arch_ != kernel_util::kArchArm)
    return false;

  if (dump.empty())
    return false;

  return RE2::PartialMatch(
      dump, RE2("(PANIC|Unhandled( Interrupt)? Exception) in EL3"));
}

bool KernelCollector::LastRebootWasNoCError(const std::string& dump) {
  // NoC errors are only on Qualcomm platforms for now.
  if (dump.empty())
    return false;

  return RE2::PartialMatch(dump, RE2("QTISECLIB.*NOC ERROR: ERRLOG"));
}

// Return true if the HW watchdog caused a reboot, so a crash report
// can be collected. Fills out `watchdog_reboot_reason` with the decoded
// reboot reason.
static bool GetWatchdogRebootReasonFromPath(
    const base::FilePath& watchdog_path, std::string& watchdog_reboot_reason) {
  std::string bootstatus_string;
  if (!base::ReadFileToString(watchdog_path, &bootstatus_string)) {
    PLOG(ERROR) << "Unable to read " << watchdog_path.value();
    return false;
  }

  int bootstatus = 0;
  if (!base::StringToInt(base::CollapseWhitespaceASCII(bootstatus_string, true),
                         &bootstatus)) {
    LOG(ERROR) << "Invalid bootstatus string '" << bootstatus_string << "'";
    return false;
  }

  // Ignore normal/unknown bootstatus.
  if (bootstatus <= 0) {
    return false;
  }

  watchdog_reboot_reason = std::string();
  uint32_t known_bootstatus_values =
      WDIOF_OVERHEAT | WDIOF_FANFAULT | WDIOF_EXTERN1 | WDIOF_EXTERN2 |
      WDIOF_POWERUNDER | WDIOF_CARDRESET | WDIOF_POWEROVER;
  if (bootstatus & ~known_bootstatus_values) {
    watchdog_reboot_reason += "-(UNKNOWN)";
    LOG(ERROR) << watchdog_path
               << ": unknown boot status value: " << std::showbase << std::hex
               << (bootstatus & ~known_bootstatus_values);
  }

  // bootstatus is a bitmap, so build up the reboot reason string.
  if (bootstatus & WDIOF_OVERHEAT)
    watchdog_reboot_reason += "-(OVERHEAT)";
  if (bootstatus & WDIOF_FANFAULT)
    watchdog_reboot_reason += "-(FANFAULT)";
  if (bootstatus & WDIOF_EXTERN1)
    watchdog_reboot_reason += "-(EXTERN1)";
  if (bootstatus & WDIOF_EXTERN2)
    watchdog_reboot_reason += "-(EXTERN2)";
  if (bootstatus & WDIOF_POWERUNDER)
    watchdog_reboot_reason += "-(POWERUNDER)";
  if (bootstatus & WDIOF_CARDRESET)
    watchdog_reboot_reason += "-(WATCHDOG)";
  if (bootstatus & WDIOF_POWEROVER)
    watchdog_reboot_reason += "-(POWEROVER)";

  // Watchdog recorded some kind of reset, so collect a crash dump.
  return true;
}

// We can't always trust kernel watchdog drivers to correctly report the boot
// reason, since on some platforms our BIOS has to reinitialize the hardware
// registers in a way that clears this information. If /sys/class/watchdog is
// unavailable, read the BIOS eventlog to figure out if a watchdog reset was
// detected during the last boot.
bool KernelCollector::LastRebootWasWatchdog(
    std::string& watchdog_reboot_reason) {
  if (base::PathExists(watchdogsys_path_)) {
    base::FilePath watchdog_sys_dir(watchdogsys_path_);
    base::FileEnumerator watchdog_sys_dir_enumerator(
        watchdog_sys_dir, false, base::FileEnumerator::DIRECTORIES);

    // Iterate through the watchdogN devices and look for a reboot.
    for (base::FilePath watchdog_path =
             watchdog_sys_dir_enumerator.Next().StripTrailingSeparators();
         !watchdog_path.empty();
         watchdog_path =
             watchdog_sys_dir_enumerator.Next().StripTrailingSeparators()) {
      // Build up the path to the watchdog's boot status:
      // For example: /sys/class/watchdog/watchdog0/bootstatus
      base::FilePath watchdog_sys_path =
          watchdog_path.Append(kWatchdogSysBootstatusFile);

      if (GetWatchdogRebootReasonFromPath(watchdog_sys_path,
                                          watchdog_reboot_reason)) {
        return true;
      }
    }
  }

  if (!base::PathExists(eventlog_path_)) {
    LOG(INFO) << "Cannot find " << eventlog_path_.value()
              << ", skipping hardware watchdog check.";
    return false;
  }

  std::string eventlog;
  if (!base::ReadFileToString(eventlog_path_, &eventlog)) {
    PLOG(ERROR) << "Unable to open " << eventlog_path_.value();
    return false;
  }

  StringPiece piece = StringPiece(eventlog);
  size_t last_boot = piece.rfind(kEventNameBoot);
  if (last_boot == StringPiece::npos)
    return false;

  watchdog_reboot_reason = "-(WATCHDOG)";
  return piece.find(kEventNameWatchdog, last_boot) != StringPiece::npos;
}

bool KernelCollector::LoadConsoleRamoops(std::string* contents) {
  FilePath record_path;

  // We assume there is only one record.  Bad idea?
  record_path =
      GetDumpRecordPath(kDumpRecordConsoleName, kDumpDriverRamoopsName, 0);

  // Deal with the filename change starting with linux-3.19+.
  if (!base::PathExists(record_path)) {
    // If the file doesn't exist, we might be running on an older system which
    // uses the older file name format (<linux-3.19).
    record_path =
        GetDumpRecordOldPath(kDumpRecordConsoleName, kDumpDriverRamoopsName);
    if (!base::PathExists(record_path)) {
      LOG(WARNING) << "No console-ramoops file found after watchdog reset";
      return false;
    }
  }

  if (!base::ReadFileToString(record_path, contents)) {
    PLOG(ERROR) << "Unable to open " << record_path.value();
    return false;
  }

  if (!RE2::PartialMatch(contents->substr(0, 1024), *kBasicCheckRe)) {
    LOG(WARNING) << "Found invalid console-ramoops file";
    return false;
  }

  return true;
}

bool KernelCollector::DumpDirMounted() {
  struct stat st_parent;
  if (stat(kDumpParentPath, &st_parent)) {
    PLOG(WARNING) << "Could not stat " << kDumpParentPath;
    return false;
  }

  struct stat st_dump;
  if (stat(kDumpPath, &st_dump)) {
    PLOG(WARNING) << "Could not stat " << kDumpPath;
    return false;
  }

  if (st_parent.st_dev == st_dump.st_dev) {
    LOG(WARNING) << "Dump dir " << kDumpPath << " not mounted";
    return false;
  }

  return true;
}

bool KernelCollector::Enable() {
  if (arch_ == kernel_util::kArchUnknown || arch_ >= kernel_util::kArchCount) {
    LOG(WARNING) << "KernelCollector does not understand this architecture";
    return false;
  }

  if (!DumpDirMounted()) {
    LOG(WARNING) << "Kernel does not support crash dumping";
    return false;
  }

  // To enable crashes, we will eventually need to set
  // the chnv bit in BIOS, but it does not yet work.
  LOG(INFO) << "Enabling kernel crash handling";
  is_enabled_ = true;
  return true;
}

bool KernelCollector::Collect(bool use_saved_lsb) {
  SetUseSavedLsb(use_saved_lsb);
  bool found_efi_crash = CollectEfiCrash();
  return (CollectRamoopsCrash() || found_efi_crash);
}

// Returns file path for corresponding efi crash part.
base::FilePath KernelCollector::EfiCrash::GetFilePath(uint32_t part) const {
  return collector_.dump_path_.Append(
      StringPrintf("%s-%s-%" PRIu64, kDumpRecordDmesgName, kDumpDriverEfiName,
                   GetIdForPart(part)));
}

// Get type of crash.
// Stack traces could be generated and written to efi pstore during kernel oops,
// kernel warning or kernel panic. First line contains header of format:
// <crash_type>#<crash_count> Part#<part_number>
// <crash_type> indicates when stack trace was generated. e.g. Panic#1 Part#1.
bool KernelCollector::EfiCrash::GetType(std::string* crash_type) const {
  std::string dump;
  if (base::ReadFileToString(GetFilePath(1), &dump)) {
    size_t pos = dump.find('#');
    if (pos != std::string::npos) {
      crash_type->append(dump, 0, pos);
      return true;
    }
  }
  return false;
}

// Loads efi crash to given string.
// Returns true iff all parts of crashes are copied to contents.
// In case of failure string contents might be modified.
bool KernelCollector::EfiCrash::Load(std::string* contents) const {
  // Part0 is never generated by efi driver.
  // Part number is descending, so Part1 contains last 1KiB (EFI
  // varaible size) of kmsg buffer, Part2 contains the second to last 1KiB,
  // etc....
  for (uint32_t part = max_part_; part > 0; part--) {
    std::string dump;
    if (!base::ReadFileToString(GetFilePath(part), &dump)) {
      PLOG(ERROR) << "Unable to open->read file for crash:" << id_
                  << " part: " << part;
      return false;
    }
    // Strip first line since it contains header e.g. Panic#1 Part#1.
    contents->append(dump, dump.find('\n') + 1, std::string::npos);
  }
  return true;
}

// Removes efi crash represented by efi variables from pstore.
void KernelCollector::EfiCrash::Remove() const {
  // Delete efi crash.
  // Part can be deleted in any order, start from Part1 since Part0 is
  // never generated.
  for (uint32_t part = 1; part <= max_part_; part++) {
    base::DeleteFile(GetFilePath(part));
  }
}

// Find number of efi crashes at /sys/fs/pstore and returns vector of EfiCrash.
std::vector<KernelCollector::EfiCrash> KernelCollector::FindEfiCrashes() const {
  std::vector<EfiCrash> efi_crashes;
  const base::FilePath pstore_dir(dump_path_);
  if (!base::PathExists(pstore_dir)) {
    return efi_crashes;
  }

  // Scan /sys/fs/pstore/.
  std::string efi_crash_pattern =
      StringPrintf("%s-%s-*", kDumpRecordDmesgName, kDumpDriverEfiName);
  base::FileEnumerator efi_file_iter(
      pstore_dir, false, base::FileEnumerator::FILES, efi_crash_pattern);

  for (auto efi_file = efi_file_iter.Next(); !efi_file.empty();
       efi_file = efi_file_iter.Next()) {
    uint64_t crash_id;
    if (!base::StringToUint64(
            efi_file.BaseName().value().substr(efi_crash_pattern.length() - 1),
            &crash_id)) {
      // This should not ever happen.
      LOG(ERROR) << "Failed to parse efi file name:"
                 << efi_file.BaseName().value();
      continue;
    }

    const uint64_t keyed_crash_id = EfiCrash::GetIdForPart(crash_id, 1);
    std::vector<EfiCrash>::iterator it =
        std::find_if(efi_crashes.begin(), efi_crashes.end(),
                     [keyed_crash_id](const EfiCrash& efi_crash) -> bool {
                       return efi_crash.GetId() == keyed_crash_id;
                     });
    if (it != efi_crashes.end()) {
      // Update part number if its greater.
      it->UpdateMaxPart(crash_id);

    } else {
      // New crash detected.
      EfiCrash efi_crash(keyed_crash_id, *this);
      efi_crash.UpdateMaxPart(crash_id);
      efi_crashes.push_back(efi_crash);
    }
  }
  return efi_crashes;
}

// Safely writes the string to the named log file.
void KernelCollector::AddLogFile(const char* log_name,
                                 const std::string& log_data,
                                 const FilePath& log_path) {
  if (!log_data.empty()) {
    if (WriteNewFile(log_path, log_data) !=
        static_cast<int>(log_data.length())) {
      PLOG(WARNING) << "Failed to write " << log_name << " to "
                    << log_path.value() << " (ignoring)";
    } else {
      AddCrashMetaUploadFile(log_name, log_path.BaseName().value());
      LOG(INFO) << "Stored " << log_name << " to " << log_path.value();
    }
  }
}

// Stores crash pointed by kernel_dump to crash directory. This will be later
// sent to backend from crash directory by crash_sender.
bool KernelCollector::HandleCrash(const std::string& kernel_dump,
                                  const std::string& bios_dump,
                                  const std::string& hypervisor_dump,
                                  const std::string& signature) {
  FilePath root_crash_directory;

  LOG(INFO) << "Received prior crash notification from "
            << "kernel (signature " << signature << ") (handling)";

  if (!GetCreatedCrashDirectoryByEuid(constants::kRootUid,
                                      &root_crash_directory, nullptr)) {
    return true;
  }

  std::string dump_basename = FormatDumpBasename(kernel_util::kKernelExecName,
                                                 time(nullptr), kKernelPid);
  FilePath kernel_crash_path = root_crash_directory.Append(
      StringPrintf("%s.kcrash", dump_basename.c_str()));
  FilePath bios_dump_path = root_crash_directory.Append(
      StringPrintf("%s.%s", dump_basename.c_str(), kBiosDumpName));
  FilePath hypervisor_dump_path = root_crash_directory.Append(
      StringPrintf("%s.%s", dump_basename.c_str(), kHypervisorDumpName));
  FilePath log_path = root_crash_directory.Append(
      StringPrintf("%s.log", dump_basename.c_str()));

  // We must use WriteNewFile instead of base::WriteFile as we
  // do not want to write with root access to a symlink that an attacker
  // might have created.
  if (WriteNewFile(kernel_crash_path, kernel_dump) !=
      static_cast<int>(kernel_dump.length())) {
    LOG(INFO) << "Failed to write kernel dump to "
              << kernel_crash_path.value().c_str();
    return true;
  }
  AddLogFile(kBiosDumpName, bios_dump, bios_dump_path);
  AddLogFile(kHypervisorDumpName, hypervisor_dump, hypervisor_dump_path);

  AddCrashMetaData(kKernelSignatureKey, signature);

  // Collect additional logs if one is specified in the config file.
  if (GetLogContents(log_config_path_, kernel_util::kKernelExecName,
                     log_path)) {
    AddCrashMetaUploadFile("log", log_path.BaseName().value());
  }

  const char* exec_name = kernel_util::IsHypervisorCrash(kernel_dump)
                              ? kernel_util::kHypervisorExecName
                              : kernel_util::kKernelExecName;

  FinishCrash(root_crash_directory.Append(
                  StringPrintf("%s.meta", dump_basename.c_str())),
              exec_name, kernel_crash_path.BaseName().value());

  LOG(INFO) << "Stored kcrash to " << kernel_crash_path.value();

  return true;
}

// CollectEfiCrash looks at /sys/fs/pstore and extracts crashes written via
// efi-pstore.
bool KernelCollector::CollectEfiCrash() {
  // List of efi crashes.
  std::vector<KernelCollector::EfiCrash> efi_crashes = FindEfiCrashes();

  LOG(INFO) << "Found " << efi_crashes.size()
            << " kernel crashes in efi-pstore.";
  // Now read each crash in buffer and cleanup pstore.
  std::vector<EfiCrash>::const_iterator efi_crash;
  for (efi_crash = efi_crashes.begin(); efi_crash != efi_crashes.end();
       ++efi_crash) {
    LOG(INFO) << "Generating kernel efi crash id:" << efi_crash->GetId();

    std::string crash_type, crash;
    if (efi_crash->GetType(&crash_type)) {
      if (crash_type == "Panic" && efi_crash->Load(&crash)) {
        LOG(INFO) << "Reporting kernel efi crash id:" << efi_crash->GetId()
                  << " type:" << crash_type;
        StripSensitiveData(&crash);
        if (!crash.empty()) {
          if (!HandleCrash(
                  crash, std::string(), "",
                  kernel_util::ComputeKernelStackSignature(crash, arch_))) {
            LOG(ERROR) << "Failed to handle kernel efi crash id:"
                       << efi_crash->GetId();
          }
        }
      } else {
        LOG(WARNING) << "Ignoring kernel efi crash id:" << efi_crash->GetId()
                     << " type:" << crash_type;
      }
    }
    // Remove efi-pstore files corresponding to crash.
    efi_crash->Remove();
  }
  return !efi_crashes.empty();
}

bool KernelCollector::CollectRamoopsCrash() {
  std::string bios_dump;
  std::string kernel_dump;
  std::string console_dump;
  std::string hypervisor_dump;
  std::string signature;
  std::string watchdog_reboot_reason;

  LoadLastBootBiosLog(&bios_dump);
  LoadConsoleRamoops(&console_dump);
  kernel_util::ExtractHypervisorLog(console_dump, hypervisor_dump);
  if (LoadParameters() && LoadPreservedDump(&kernel_dump)) {
    signature = kernel_util::ComputeKernelStackSignature(kernel_dump, arch_);
  } else {
    kernel_dump = std::move(console_dump);
    if (LastRebootWasBiosCrash(bios_dump)) {
      signature = kernel_util::BiosCrashSignature(bios_dump);
    } else if (LastRebootWasNoCError(bios_dump)) {
      signature = kernel_util::ComputeNoCErrorSignature(bios_dump);
    } else if (LastRebootWasWatchdog(watchdog_reboot_reason)) {
      signature =
          kernel_util::WatchdogSignature(kernel_dump, watchdog_reboot_reason);
    } else {
      return false;
    }
  }
  StripSensitiveData(&bios_dump);
  StripSensitiveData(&hypervisor_dump);
  StripSensitiveData(&kernel_dump);
  if (kernel_dump.empty() && bios_dump.empty() && hypervisor_dump.empty()) {
    return false;
  }
  return HandleCrash(kernel_dump, bios_dump, hypervisor_dump, signature);
}
