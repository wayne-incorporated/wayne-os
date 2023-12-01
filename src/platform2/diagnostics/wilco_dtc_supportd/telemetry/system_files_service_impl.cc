// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/telemetry/system_files_service_impl.h"

#include <optional>
#include <utility>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_util.h>

namespace diagnostics {
namespace wilco {

// static
base::FilePath SystemFilesServiceImpl::GetPathForFile(
    SystemFilesService::File location) {
  switch (location) {
    case File::kProcUptime:
      return base::FilePath("proc/uptime");
    case File::kProcMeminfo:
      return base::FilePath("proc/meminfo");
    case File::kProcLoadavg:
      return base::FilePath("proc/loadavg");
    case File::kProcStat:
      return base::FilePath("proc/stat");
    case File::kProcNetNetstat:
      return base::FilePath("proc/net/netstat");
    case File::kProcNetDev:
      return base::FilePath("proc/net/dev");
    case File::kProcDiskstats:
      return base::FilePath("proc/diskstats");
    case File::kProcCpuinfo:
      return base::FilePath("proc/cpuinfo");
    case File::kProcVmstat:
      return base::FilePath("proc/vmstat");
  }

  NOTREACHED();
}

// static
base::FilePath SystemFilesServiceImpl::GetPathForDirectory(
    SystemFilesService::Directory location) {
  switch (location) {
    case Directory::kProcAcpiButton:
      return base::FilePath("proc/acpi/button/");
    case Directory::kSysClassHwmon:
      return base::FilePath("sys/class/hwmon/");
    case Directory::kSysClassThermal:
      return base::FilePath("sys/class/thermal/");
    case Directory::kSysFirmwareDmiTables:
      return base::FilePath("sys/firmware/dmi/tables/");
    case Directory::kSysClassPowerSupply:
      return base::FilePath("sys/class/power_supply/");
    case Directory::kSysClassBacklight:
      return base::FilePath("sys/class/backlight/");
    case Directory::kSysClassNetwork:
      return base::FilePath("sys/class/net/");
    case Directory::kSysDevicesSystemCpu:
      return base::FilePath("sys/devices/system/cpu/");
  }

  NOTREACHED();
}

// static
base::FilePath SystemFilesServiceImpl::GetPathForVpdField(VpdField vpd_field) {
  switch (vpd_field) {
    case VpdField::kActivateDate:
      return base::FilePath("run/wilco_dtc/vpd_fields/ActivateDate");
    case VpdField::kAssetId:
      return base::FilePath("run/wilco_dtc/vpd_fields/asset_id");
    case VpdField::kMfgDate:
      return base::FilePath("run/wilco_dtc/vpd_fields/mfg_date");
    case VpdField::kModelName:
      return base::FilePath("run/wilco_dtc/vpd_fields/model_name");
    case VpdField::kSerialNumber:
      return base::FilePath("run/wilco_dtc/vpd_fields/serial_number");
    case VpdField::kSkuNumber:
      return base::FilePath("run/wilco_dtc/vpd_fields/sku_number");
    case VpdField::kSystemId:
      return base::FilePath("run/wilco_dtc/vpd_fields/system_id");
    case VpdField::kUuid:
      return base::FilePath("run/wilco_dtc/vpd_fields/uuid_id");
  }

  NOTREACHED();
}

SystemFilesServiceImpl::SystemFilesServiceImpl() = default;

SystemFilesServiceImpl::~SystemFilesServiceImpl() = default;

std::optional<SystemFilesService::FileDump> SystemFilesServiceImpl::GetFileDump(
    File location) {
  FileDump dump;
  if (!MakeFileDump(root_dir_.Append(GetPathForFile(location)), &dump)) {
    return std::nullopt;
  }
  return std::move(dump);
}

std::optional<SystemFilesService::FileDumps>
SystemFilesServiceImpl::GetDirectoryDump(Directory location) {
  base::FilePath path = root_dir_.Append(GetPathForDirectory(location));
  if (!base::DirectoryExists(path))
    return std::nullopt;

  FileDumps dumps;
  std::set<std::string> visited_paths;
  SearchDirectory(path, &visited_paths, &dumps);

  return std::move(dumps);
}

std::optional<std::string> SystemFilesServiceImpl::GetVpdField(
    VpdField vpd_field) {
  FileDump dump;
  if (!MakeFileDump(root_dir_.Append(GetPathForVpdField(vpd_field)), &dump)) {
    return std::nullopt;
  }

  base::TrimString(dump.contents, base::kWhitespaceASCII, &dump.contents);
  if (dump.contents.empty() || !base::IsStringASCII(dump.contents)) {
    VLOG(2) << "VPD field from " << GetPathForVpdField(vpd_field).BaseName()
            << " is not non-empty ASCII string";
    return std::nullopt;
  }

  return std::move(dump.contents);
}

void SystemFilesServiceImpl::set_root_dir_for_testing(
    const base::FilePath& dir) {
  root_dir_ = dir;
}

bool SystemFilesServiceImpl::MakeFileDump(const base::FilePath& file_path,
                                          FileDump* file_dump) const {
  std::string file_contents;
  if (!base::ReadFileToString(file_path, &file_contents)) {
    VPLOG(2) << "Failed to read from " << file_path.value();
    return false;
  }
  const base::FilePath canonical_file_path =
      base::MakeAbsoluteFilePath(file_path);
  if (canonical_file_path.empty()) {
    PLOG(ERROR) << "Failed to obtain canonical path for " << file_path.value();
    return false;
  }
  VLOG(3) << "Read " << file_contents.size() << " bytes from "
          << file_path.value() << " with canonical path "
          << canonical_file_path.value();

  file_dump->path = file_path;
  file_dump->canonical_path = canonical_file_path;
  file_dump->contents = std::move(file_contents);
  return true;
}

void SystemFilesServiceImpl::SearchDirectory(
    const base::FilePath& root_dir,
    std::set<std::string>* visited_paths,
    FileDumps* file_dumps) const {
  visited_paths->insert(base::MakeAbsoluteFilePath(root_dir).value());
  base::FileEnumerator file_enum(
      base::FilePath(root_dir), false,
      base::FileEnumerator::FileType::FILES |
          base::FileEnumerator::FileType::DIRECTORIES |
          base::FileEnumerator::FileType::SHOW_SYM_LINKS);
  for (base::FilePath path = file_enum.Next(); !path.empty();
       path = file_enum.Next()) {
    // Only certain symlinks are followed - see the comments for
    // ShouldFollowSymlink for a full description of the behavior.
    if (base::IsLink(path) && !ShouldFollowSymlink(path))
      continue;

    base::FilePath canonical_path = base::MakeAbsoluteFilePath(path);
    if (canonical_path.empty()) {
      VPLOG(2) << "Failed to resolve path '" << path.value() << "'.";
      continue;
    }

    // Prevent visiting duplicate paths, which could happen due to following
    // symlinks.
    if (visited_paths->find(canonical_path.value()) != visited_paths->end())
      continue;

    visited_paths->insert(canonical_path.value());

    if (base::DirectoryExists(path)) {
      SearchDirectory(path, visited_paths, file_dumps);
    } else {
      auto file_dump = std::make_unique<FileDump>();
      if (!MakeFileDump(path, file_dump.get())) {
        // When a file is failed to be dumped, it's just omitted from the
        // returned list of entries.
        continue;
      }
      file_dumps->push_back(std::move(file_dump));
    }
  }
}

bool SystemFilesServiceImpl::ShouldFollowSymlink(
    const base::FilePath& link) const {
  // Path relative to the root directory where we will follow symlinks.
  constexpr char kAllowableSymlinkParentDir[] = "sys/class";
  return base::FilePath(root_dir_.Append(kAllowableSymlinkParentDir)) ==
         link.DirName().DirName();
}

}  // namespace wilco
}  // namespace diagnostics
