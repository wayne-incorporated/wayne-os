// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/arcpp_cxx_collector.h"

#include <sysexits.h>
#include <unistd.h>

#include <ctime>
#include <utility>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringize_macros.h>
#include <base/time/time.h>
#include <brillo/key_value_store.h>
#include <brillo/process/process.h>

#include "crash-reporter/arc_util.h"
#include "crash-reporter/util.h"

using base::FilePath;
using base::ReadFileToString;

using brillo::ProcessImpl;

namespace {

// "native_crash" is a tag defined in Android.
const char kCrashType[] = "native_crash";

const FilePath kContainersDir("/run/containers");
const char kArcDirPattern[] = "android*";
const FilePath kContainerPid("container.pid");

const char kArcBuildProp[] = "/run/arc/host_generated/build.prop";

const char kCoreCollectorPath[] = "/usr/bin/core_collector";
const char kCoreCollector32Path[] = "/usr/bin/core_collector32";
const char kCoreCollector64Path[] = "/usr/bin/core_collector64";

// Keys for build properties.
const char kAbiMigrationStateProperty[] = "arc.abi.migrationstatus";

inline bool IsAppProcess(const std::string& name) {
  return name == "app_process32" || name == "app_process64";
}

bool GetArcRoot(FilePath* root);
// Get ARC primary ABI 32 bits to 64 bits migration status from ARC container.
// This is for container only. ARCVM should have separate implementation.
// See b/170238737 for detail.
bool GetAbiMigrationState(std::string* state);

}  // namespace

ArcppCxxCollector::ArcppCxxCollector()
    : ArcppCxxCollector(ContextPtr(new ArcContext(this))) {}

ArcppCxxCollector::ArcppCxxCollector(ContextPtr context)
    : UserCollectorBase("ARCPP_cxx", kAlwaysUseUserCrashDirectory),
      context_(std::move(context)) {}

bool ArcppCxxCollector::IsArcProcess(pid_t pid) const {
  pid_t arc_pid;
  if (!context_->GetArcPid(&arc_pid)) {
    LOG(ERROR) << "Failed to get PID of ARC container";
    return false;
  }
  std::string arc_ns;
  if (!context_->GetPidNamespace(arc_pid, &arc_ns)) {
    LOG(ERROR) << "Failed to get PID namespace of ARC container";
    return false;
  }
  std::string ns;
  if (!context_->GetPidNamespace(pid, &ns)) {
    LOG(ERROR) << "Failed to get PID namespace of process";
    return false;
  }
  return ns == arc_ns;
}

// static
bool ArcppCxxCollector::IsArcRunning() {
  return GetArcPid(nullptr);
}

// static
bool ArcppCxxCollector::GetArcPid(pid_t* arc_pid) {
  base::FileEnumerator containers(
      kContainersDir, false, base::FileEnumerator::DIRECTORIES, kArcDirPattern);

  for (FilePath container = containers.Next(); !container.empty();
       container = containers.Next()) {
    std::string contents;
    if (!ReadFileToString(container.Append(kContainerPid), &contents) ||
        contents.empty())
      continue;

    contents.pop_back();  // Trim EOL.

    pid_t pid;
    if (!base::StringToInt(contents, &pid) ||
        !base::PathExists(GetProcessPath(pid)))
      continue;

    if (arc_pid)
      *arc_pid = pid;

    return true;
  }

  return false;
}

bool ArcppCxxCollector::ArcContext::GetArcPid(pid_t* pid) const {
  return ArcppCxxCollector::GetArcPid(pid);
}

bool ArcppCxxCollector::ArcContext::GetPidNamespace(pid_t pid,
                                                    std::string* ns) const {
  const FilePath path = GetProcessPath(pid).Append("ns").Append("pid");

  // The /proc/[pid]/ns/pid file is a special symlink that resolves to a string
  // containing the inode number of the PID namespace, e.g. "pid:[4026531838]".
  FilePath target;
  if (!base::ReadSymbolicLink(path, &target)) {
    PLOG(ERROR) << "Failed reading symbolic link: " << path.value();
    return false;
  }

  *ns = target.value();
  return true;
}

bool ArcppCxxCollector::ArcContext::GetExecBaseNameAndDirectory(
    pid_t pid, std::string* exec, base::FilePath* exec_directory) const {
  return collector_->CrashCollector::GetExecutableBaseNameAndDirectoryFromPid(
      pid, exec, exec_directory);
}

bool ArcppCxxCollector::ArcContext::GetCommand(pid_t pid,
                                               std::string* command) const {
  std::vector<std::string> args = collector_->GetCommandLine(pid);
  if (args.size() == 0)
    return false;
  // Return the command and discard the arguments.
  *command = args[0];
  return true;
}

bool ArcppCxxCollector::ArcContext::ReadAuxvForProcess(
    pid_t pid, std::string* contents) const {
  // The architecture with the largest auxv size is powerpc with 400 bytes.
  // Round it up to the next power of two.
  constexpr size_t kMaxAuxvSize = 512;
  const FilePath auxv_path = GetProcessPath(pid).Append("auxv");
  return base::ReadFileToStringWithMaxSize(auxv_path, contents, kMaxAuxvSize);
}

std::string ArcppCxxCollector::GetProductVersion() const {
  return arc_util::GetProductVersion();
}

bool ArcppCxxCollector::GetExecutableBaseNameAndDirectoryFromPid(
    pid_t pid, std::string* base_name, base::FilePath* exec_directory) {
  if (!context_->GetExecBaseNameAndDirectory(pid, base_name, exec_directory))
    return false;

  // The runtime for non-native ARC apps overwrites its command line with the
  // package name of the app, so use that instead.
  if (IsArcProcess(pid) && IsAppProcess(*base_name)) {
    if (!context_->GetCommand(pid, base_name))
      LOG(ERROR) << "Failed to get package name";
  }
  return true;
}

bool ArcppCxxCollector::ShouldDump(pid_t pid,
                                   uid_t uid,
                                   const std::string& exec,
                                   std::string* reason) {
  if (!IsArcProcess(pid)) {
    *reason = "ignoring - crash origin is not ARC";
    return false;
  }

  if (uid >= kSystemUserEnd) {
    *reason = "ignoring - not a system process";
    return false;
  }

  return UserCollectorBase::ShouldDump(reason);
}

UserCollectorBase::ErrorType ArcppCxxCollector::ConvertCoreToMinidump(
    pid_t pid,
    const base::FilePath& container_dir,
    const base::FilePath& core_path,
    const base::FilePath& minidump_path) {
  FilePath root;
  if (!GetArcRoot(&root)) {
    LOG(ERROR) << "Failed to get ARC root";
    return kErrorSystemIssue;
  }

  const char* collector_path = kCoreCollectorPath;
  bool is_64_bit;
  ErrorType elf_class_error = Is64BitProcess(pid, &is_64_bit);
  // Still try to run core_collector32 if 64-bit detection failed.
  if (__WORDSIZE == 64 && (elf_class_error != kErrorNone || !is_64_bit))
    collector_path = kCoreCollector32Path;

  // Still try to run core_collector64 if 64-bit detection failed.
  if (__WORDSIZE == 32 && (elf_class_error != kErrorNone || is_64_bit))
    collector_path = kCoreCollector64Path;

  ProcessImpl core_collector;
  core_collector.AddArg(collector_path);
  core_collector.AddArg("--minidump");
  core_collector.AddArg(minidump_path.value());
  core_collector.AddArg("--coredump");
  core_collector.AddArg(core_path.value());
  core_collector.AddArg("--proc");
  core_collector.AddArg(container_dir.value());
  core_collector.AddArg("--prefix");
  core_collector.AddArg(root.value());

  std::string error;
  int exit_code =
      util::RunAndCaptureOutput(&core_collector, STDERR_FILENO, &error);

  if (exit_code < 0) {
    PLOG(ERROR) << "Failed to start " << collector_path;
    return kErrorSystemIssue;
  }

  if (exit_code == EX_OK) {
    std::string process;
    base::FilePath exec_directory;
    ArcppCxxCollector::GetExecutableBaseNameAndDirectoryFromPid(
        pid, &process, &exec_directory);
    AddArcMetaData(process);
    return kErrorNone;
  }

  util::LogMultilineError(error);

  LOG(ERROR) << collector_path << " failed with exit code " << exit_code;
  switch (exit_code) {
    case EX_OSFILE:
      return kErrorInvalidCoreFile;
    case EX_SOFTWARE:
      return kErrorCore2MinidumpConversion;
    default:
      return base::PathExists(core_path) ? kErrorSystemIssue
                                         : kErrorReadCoreData;
  }
}

void ArcppCxxCollector::AddArcMetaData(const std::string& process) {
  for (const auto& metadata :
       arc_util::ListBasicARCRelatedMetadata(process, kCrashType)) {
    AddCrashMetaUploadData(metadata.first, metadata.second);
  }
  AddCrashMetaUploadData(arc_util::kChromeOsVersionField, GetOsVersion());

  SetUpDBus();
  base::TimeDelta uptime;
  if (arc_util::GetArcContainerUptime(session_manager_proxy_.get(), &uptime)) {
    AddCrashMetaUploadData(arc_util::kUptimeField,
                           arc_util::FormatDuration(uptime));
  }

  if (arc_util::IsSilentReport(kCrashType))
    AddCrashMetaData(arc_util::kSilentKey, "true");

  arc_util::BuildProperty build_property;
  if (GetArcProperties(FilePath(kArcBuildProp), &build_property)) {
    for (const auto& metadata :
         arc_util::ListMetadataForBuildProperty(build_property)) {
      AddCrashMetaUploadData(metadata.first, metadata.second);
    }
  }
  std::string abi_migration_state;
  // Error logging sits inside |GetAbiMigrationState|
  if (GetAbiMigrationState(&abi_migration_state)) {
    AddCrashMetaUploadData(arc_util::kAbiMigrationField, abi_migration_state);
  }
}

UserCollectorBase::ErrorType ArcppCxxCollector::Is64BitProcess(
    int pid, bool* is_64_bit) const {
  std::string auxv_contents;
  if (!context_->ReadAuxvForProcess(pid, &auxv_contents)) {
    PLOG(ERROR) << "Could not read /proc/" << pid << "/auxv";
    return kErrorSystemIssue;
  }
  // auxv is an array of unsigned long[2], and the first element in each entry
  // is an AT_* key. We assume we are running a 32-bit process (hence the
  // |*is_64_bit| below), and then try to see if any of the keys seem off.
  // All AT_* keys are less than ~48, so if we find any key that exceeds 256, we
  // definitely know it is not a 32-bit process. This will almost always trigger
  // correctly because some of the values in the auxv are pointers and their
  // high bits are almost always non-zero. For illustration purposes, consider
  // the following auxv taken from a x86_64 machine:
  //
  // |-------64-bit key------|-----64-bit value------|
  // |32-bit key-|32-bit val-|32-bit key-|32-bit val-|
  //  21 00 00 00 00 00 00 00 00 30 db e6 fe 7f 00 00
  //  10 00 00 00 00 00 00 00 ff fb eb bf 00 00 00 00
  //  06 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00
  //  ...
  //
  //  When interpreted as 64-bit unsigned longs, all the keys are less than 256,
  //  but when interpreted as 32-bit unsigned longs, some of the "keys" will
  //  contain the upper parts of addresses.
  struct Auxv32BitEntry {
    uint32_t key;
    uint32_t value;
  };
  if (auxv_contents.size() % sizeof(Auxv32BitEntry) != 0) {
    LOG(ERROR) << "Could not parse the contents of the auxv file. "
               << "Size not a multiple of 8: " << auxv_contents.size();
    return kErrorSystemIssue;
  }
  *is_64_bit = false;

  const Auxv32BitEntry* auxv_32_bit_entries =
      reinterpret_cast<const Auxv32BitEntry*>(auxv_contents.data());
  const size_t auxv_32_bit_entries_length =
      auxv_contents.size() / sizeof(Auxv32BitEntry);

  for (size_t i = 0; i < auxv_32_bit_entries_length; ++i) {
    if (auxv_32_bit_entries[i].key > 256) {
      *is_64_bit = true;
      break;
    }
  }

  return kErrorNone;
}

bool GetArcProperties(const base::FilePath& build_prop_path,
                      arc_util::BuildProperty* build_property) {
  FilePath root;
  brillo::KeyValueStore store;
  // The property name used in kArcBuildProp for the device name differs based
  // on the Android version. This only applies to the host-generated file. In
  // final set of system properties visible to the guest, both properties
  // appear.

  if (!store.Load(build_prop_path)) {
    LOG(ERROR) << "Failed to load build prop file: " << kArcBuildProp;
    return false;
  }

  // See
  // http://cs/chromeos_internal/src/private-overlays/project-cheets-private/scripts/board_specific_setup.py?l=960-966
  if (!store.GetString(kDevicePropertyP, &(build_property->device)) &&
      !store.GetString(kDevicePropertyR, &(build_property->device))) {
    LOG(ERROR) << "Failed to get device property";
    return false;
  }

  if (store.GetString(kFingerprintProperty, &(build_property->fingerprint)) &&
      store.GetString(kBoardProperty, &(build_property->board)) &&
      store.GetString(kCpuAbiProperty, &(build_property->cpu_abi)))
    return true;

  LOG(ERROR) << "Failed to get ARC properties";
  return false;
}

namespace {

bool GetArcRoot(FilePath* root) {
  base::FileEnumerator containers(
      kContainersDir, false, base::FileEnumerator::DIRECTORIES, kArcDirPattern);

  for (FilePath container = containers.Next(); !container.empty();
       container = containers.Next()) {
    const FilePath path = container.Append("root");
    if (base::PathExists(path)) {
      *root = path;
      return true;
    }
  }

  return false;
}

bool GetAbiMigrationState(std::string* state) {
  brillo::ProcessImpl androidsh;
  androidsh.AddArg("/usr/sbin/android-sh");
  androidsh.AddArg("-c");
  androidsh.AddArg(std::string("getprop ") + kAbiMigrationStateProperty);

  base::FilePath temp_file;
  if (!base::CreateTemporaryFile(&temp_file)) {
    LOG(ERROR) << "Fail to create tmp file to receive result from getprop cmd.";
    return false;
  }
  androidsh.RedirectOutput(temp_file.value());
  int result = androidsh.Run();
  if (result == 0) {
    if (!base::ReadFileToString(temp_file, state)) {
      LOG(ERROR) << "Fail to read result of getprop cmd from tmp file";
      return false;
    }
    base::TrimWhitespaceASCII(*state, base::TRIM_TRAILING, state);
    return !state->empty();
  } else {
    LOG(ERROR) << "Process for android-sh fail to run, err code: " << result;
    return false;
  }
}

}  // namespace
