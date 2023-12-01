// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The udev collector grabs coredumps from hardware devices.
//
// For the most part, this only collects information on developer images (since
// device coredumps could include information we don't want to upload).
// However, it does grab wifi chip dumps and put them in a /var/log to be
// uploaded with feedback reports, but does NOT upload them with crash reports.
//
// The udev collector is invoked automatically by the udev rules in
// 99-crash-reporter.rules when certain classes of devices have errors.

#ifndef CRASH_REPORTER_UDEV_COLLECTOR_H_
#define CRASH_REPORTER_UDEV_COLLECTOR_H_

#include <map>
#include <string>

#include <base/files/file_path.h>

#include "crash-reporter/crash_collector.h"

// Udev crash collector.
class UdevCollector : public CrashCollector {
 public:
  UdevCollector();
  UdevCollector(const UdevCollector&) = delete;
  UdevCollector& operator=(const UdevCollector&) = delete;

  ~UdevCollector() override;

  // The udev event string should be formatted as follows:
  //   "ACTION=[action]:KERNEL=[name]:SUBSYSTEM=[subsystem]"
  // The values don't have to be in any particular order. One or more of them
  // could be omitted, in which case it would be treated as a wildcard (*).
  bool HandleCrash(const std::string& udev_event);

  static CollectorInfo GetHandlerInfo(const std::string& udev_event);

 protected:
  std::string dev_coredump_directory_;

 private:
  friend class UdevCollectorTest;

  // Is this a "safe" device coredump, from an allowlist of driver names
  // for devices whose device coredump does not contain PII?
  bool IsSafeDevCoredump(std::map<std::string, std::string> udev_event_map);

  // Process udev crash logs, collecting log files according to the config
  // file (crash_reporter_logs.conf).
  bool ProcessUdevCrashLogs(const base::FilePath& crash_directory,
                            const std::string& action,
                            const std::string& kernel,
                            const std::string& subsystem);
  // Process device coredump, collecting device coredump file.
  // |instance_number| is the kernel number of the virtual device for the device
  // coredump instance.
  bool ProcessDevCoredump(const base::FilePath& crash_directory,
                          int instance_number);
  // Copy bluetooth device coredump file to crash directory, and perform
  // necessary coredump file management.
  bool AppendBluetoothCoredump(const base::FilePath& crash_directory,
                               const base::FilePath& coredump_path,
                               int instance_number);
  // Copy device coredump file to crash directory, and perform necessary
  // coredump file management.
  bool AppendDevCoredump(const base::FilePath& crash_directory,
                         const base::FilePath& coredump_path,
                         int instance_number);
  // Clear the device coredump file by performing a dummy write to it.
  bool ClearDevCoredump(const base::FilePath& coredump_path);
  // Generate the driver path of the failing device from instance and sub-path.
  base::FilePath GetFailingDeviceDriverPath(int instance_number,
                                            const std::string& sub_path);
  // Get the driver name of the failing device from uevent path.
  std::string ExtractFailingDeviceDriverName(
      const base::FilePath& failing_uevent_path);
  // Return the driver name of the device that generates the coredump.
  std::string GetFailingDeviceDriverName(int instance_number);
};

#endif  // CRASH_REPORTER_UDEV_COLLECTOR_H_
