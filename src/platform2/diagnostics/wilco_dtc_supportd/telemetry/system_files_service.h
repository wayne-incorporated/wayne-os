// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_SYSTEM_FILES_SERVICE_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_SYSTEM_FILES_SERVICE_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace diagnostics {
namespace wilco {

class SystemFilesService {
 public:
  struct FileDump {
    FileDump();
    ~FileDump();

    FileDump(FileDump&& other);
    FileDump& operator=(FileDump&& other);

    // Absolute path to the file.
    base::FilePath path;
    // Canonicalized path to the file. Unlike |path|, this path never contains
    // symbolic links.
    base::FilePath canonical_path;
    std::string contents;
  };

  using FileDumps = std::vector<std::unique_ptr<FileDump>>;

  enum class Directory {
    kProcAcpiButton,  // request contents of files under
                      // “/proc/acpi/button/"

    kSysClassHwmon,    // request information about hwmon devices (contents of
                       // files under /sys/class/hwmon/)
    kSysClassThermal,  // request information about thermal zone devices and
                       // cooling devices (contents of files under
                       // /sys/class/thermal/)
    kSysFirmwareDmiTables,  // request SMBIOS information as raw DMI tables
                            // (contents of files under
                            // /sys/firmware/dmi/tables/)
    kSysClassPowerSupply,   // request information about power supplies
                            // (contents of files under
                            // /sys/class/power_supply/)
    kSysClassBacklight,     // request information about brightness
                            // (contents of files under /sys/class/backlight/)
    kSysClassNetwork,       // request information about WLAN and Ethernet
                            // (contents of files under /sys/class/net/)
    kSysDevicesSystemCpu,   // request information about CPU details.
                            // (contents of files under
                            // /sys/devices/system/cpu/)
  };

  enum class File {
    kProcUptime,      // request contents of "/proc/uptime"
    kProcMeminfo,     // request contents of “/proc/meminfo"
    kProcLoadavg,     // request contents of “/proc/loadavg"
    kProcStat,        // request contents of “/proc/stat"
    kProcNetNetstat,  // request contents of “/proc/net/netstat"
    kProcNetDev,      // request contents of “/proc/net/dev"
    kProcDiskstats,   // request contents of “/proc/diskstats"
    kProcCpuinfo,     // request contents of “/proc/cpuinfo"
    kProcVmstat,      // request contents of “/proc/vmstat"
  };

  enum class VpdField {
    kActivateDate,  // request value of ActivateDate VPD field
    kAssetId,       // request value of AssetId VPD field
    kMfgDate,       // request value of MfgDate VPD field
    kModelName,     // request value of ModelName VPD field
    kSerialNumber,  // request value of SerialNumber VPD field
    kSkuNumber,     // request value of SkuNumber VPD field
    kSystemId,      // request value of SystemId VPD field
    kUuid,          // request value of Uuid VPD field
  };

  SystemFilesService() = default;
  SystemFilesService(const SystemFilesService&) = delete;
  SystemFilesService& operator=(const SystemFilesService&) = delete;

  virtual ~SystemFilesService() = default;

  // Gets the dump of the specified file. Returns std::nullopt on failure.
  virtual std::optional<FileDump> GetFileDump(File location) = 0;

  // Gets the dumps of the files in the specified directory.  Returns true if
  // successful.
  virtual std::optional<FileDumps> GetDirectoryDump(Directory location) = 0;

  // Gets trimmed value of the specified VPD field.
  // Returns std::nullopt if VPD value does not exist, empty or contains
  // non-ASCII symbols.
  // TODO(b/154595154): consider changing behavior: empty string is valid, non
  // ASCII symbols are allowed.
  virtual std::optional<std::string> GetVpdField(VpdField vpd_field) = 0;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_SYSTEM_FILES_SERVICE_H_
