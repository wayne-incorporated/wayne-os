// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_ARC_UTIL_H_
#define CRASH_REPORTER_ARC_UTIL_H_

#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <base/time/tick_clock.h>
#include <base/time/time.h>
#include <session_manager/dbus-proxies.h>

#include "crash-reporter/crash_collector.h"

namespace arc_util {

using CrashLogHeaderMap = std::unordered_map<std::string, std::string>;

extern const char kArcProduct[];

// Metadata fields included in reports.
extern const char kAbiMigrationField[];
extern const char kAndroidVersionField[];
extern const char kArcVersionField[];
extern const char kBoardField[];
extern const char kChromeOsVersionField[];
extern const char kCpuAbiField[];
extern const char kCrashTypeField[];
extern const char kDeviceField[];
extern const char kProcessField[];
extern const char kProductField[];
extern const char kUptimeField[];

// For Java Crash
extern const char kExceptionInfoField[];
extern const char kSignatureField[];

// If this metadata key is set to "true", the report is uploaded silently, i.e.
// it does not appear in chrome://crashes.
extern const char kSilentKey[];

// Keys for crash log headers.
extern const char kProcessKey[];
extern const char kSubjectKey[];

extern const std::vector<std::pair<const char*, const char*>>
    kHeaderToFieldMapping;

// The property about ARC build. These values comes from a Mojo method,
// SetBuildProperties.
struct BuildProperty {
  std::string device;
  std::string board;
  std::string cpu_abi;
  std::string fingerprint;
};

// Returns the Android version (eg: 7.1.1) from the fingerprint.
std::optional<std::string> GetVersionFromFingerprint(
    const std::string& fingerprint);

bool ParseCrashLog(const std::string& type,
                   const std::string& contents,
                   CrashLogHeaderMap* map,
                   std::string* exception_info,
                   std::string* log);

const char* GetSubjectTag(const std::string& type);

bool IsSilentReport(const std::string& type);

std::string GetCrashLogHeader(const CrashLogHeaderMap& map, const char* key);

// Return Random PID.
// FormatDumpBasename relies on the assumption that the combination of process
// name, timestamp, and PID is unique. This does not hold if a process crashes
// more than once in the span of a second. While this is improbable for native
// crashes, Java crashes are not always fatal and may happen in bursts. Hence,
// ensure uniqueness by replacing the PID with the number of microseconds
// since the current second.
pid_t CreateRandomPID();

// Lists metadata which all ARC-related collectors should attach.
std::vector<std::pair<std::string, std::string>> ListBasicARCRelatedMetadata(
    const std::string& process, const std::string& crash_type);

// Lists metadata from |build_property| as a list of pairs of key and value.
std::vector<std::pair<std::string, std::string>> ListMetadataForBuildProperty(
    const BuildProperty& build_property);

// GetChromeVersion returns the version of Chrome browser. ARC++ and ARCVM crash
// reports use versions of Chrome browser as their product version.
bool GetChromeVersion(std::string* version);

// Returns the value which ARC-related collectors should use as the product
// version of their reports. ARC-related collectors need to override
// GetProductVersion method using this.
std::string GetProductVersion();

// Format the given time delta in human-readable manner.
std::string FormatDuration(base::TimeDelta delta);

// Return the uptime of current ARC container instance from the time when the
// container upgraded from the mini-container. This works only for ARC container
// and only after the full container is started.
bool GetArcContainerUptime(
    org::chromium::SessionManagerInterfaceProxyInterface* session_manager_proxy,
    base::TimeDelta* uptime,
    base::TickClock* test_clock = nullptr);

}  // namespace arc_util

#endif  // CRASH_REPORTER_ARC_UTIL_H_
