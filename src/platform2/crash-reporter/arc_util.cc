// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/arc_util.h"

#include <optional>
#include <sstream>

#include <stdint.h>
#include <sysexits.h>

#include <base/logging.h>
#include <brillo/process/process.h>

#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

namespace arc_util {

namespace {

constexpr char kUnknownValue[] = "unknown";

constexpr char kChromeDirectory[] = "/opt/google/chrome";

bool HasExceptionInfo(const std::string& type) {
  static const std::unordered_set<std::string> kTypes = {
      "data_app_crash", "system_app_crash", "system_app_wtf",
      "system_server_crash", "system_server_wtf"};
  return kTypes.count(type);
}

base::TimeTicks ToSeconds(const base::TimeTicks& time) {
  return base::TimeTicks::FromInternalValue(
      base::Seconds(base::TimeDelta::FromInternalValue(time.ToInternalValue())
                        .InSeconds())
          .ToInternalValue());
}

}  // namespace

using CrashLogHeaderMap = std::unordered_map<std::string, std::string>;

const char kArcProduct[] = "ChromeOS_ARC";

const char kAbiMigrationField[] = "abi_migration_status";
const char kAndroidVersionField[] = "android_version";
const char kArcVersionField[] = "arc_version";
const char kBoardField[] = "board";
const char kChromeOsVersionField[] = "chrome_os_version";
const char kCpuAbiField[] = "cpu_abi";
const char kCrashTypeField[] = "crash_type";
const char kDeviceField[] = "device";
const char kProcessField[] = "process";
const char kProductField[] = "prod";
const char kUptimeField[] = "uptime";

const char kExceptionInfoField[] = "exception_info";
const char kSignatureField[] = "sig";

const char kSilentKey[] = "silent";

const char kProcessKey[] = "Process";
const char kSubjectKey[] = "Subject";

const std::vector<std::pair<const char*, const char*>> kHeaderToFieldMapping = {
    {"Crash-Tag", "crash_tag"},
    {"NDK-Execution", "ndk_execution"},
    {"Package", "package"},
    {"Target-SDK", "target_sdk"},
    {"Abi-Migration-Status", "abi_migration_status"},
};

std::optional<std::string> GetVersionFromFingerprint(
    const std::string& fingerprint) {
  // fingerprint has the following format:
  //   $(PRODUCT_BRAND)/$(TARGET_PRODUCT)/$(TARGET_DEVICE):$(PLATFORM_VERSION)/
  //     ..$(BUILD_ID)/$(BF_BUILD_NUMBER):$(TARGET_BUILD_VARIANT)/
  //     ..$(BUILD_VERSION_TAGS)
  // eg:
  //   google/caroline/caroline_cheets:7.1.1/R65-10317.0.9999/
  //     ..4548207:user/release-keys
  // we want to get the $(PLATFORM_VERSION). eg: 7.1.1

  std::string android_version;
  // Assuming the fingerprint format won't change. Everything between ':' and
  // '/R' is the version.
  auto begin = fingerprint.find(':');
  if (begin == std::string::npos)
    return std::nullopt;

  // Make begin point to the start of the "version".
  begin++;

  // Version must have at least one digit.
  const auto end = fingerprint.find("/R", begin + 1);
  if (end == std::string::npos)
    return std::nullopt;

  return fingerprint.substr(begin, end - begin);
}

bool ParseCrashLog(const std::string& type,
                   const std::string& contents,
                   std::unordered_map<std::string, std::string>* map,
                   std::string* exception_info,
                   std::string* log) {
  std::string line;

  std::stringstream stream(contents);
  // The last header is followed by an empty line.
  while (std::getline(stream, line) && !line.empty()) {
    const auto end = line.find(':');

    if (end != std::string::npos) {
      const auto begin = line.find_first_not_of(' ', end + 1);

      if (begin != std::string::npos) {
        // TODO(domlaskowski): Use multimap to allow multiple "Package" headers.
        if (!map->emplace(line.substr(0, end), line.substr(begin)).second)
          LOG(WARNING) << "Duplicate header: " << line;
        continue;
      }
    }

    // Ignore malformed headers. The report is still created, but the associated
    // metadata fields are set to "unknown".
    LOG(WARNING) << "Header has unexpected format: " << line;
  }

  if (stream.fail())
    return false;

  if (HasExceptionInfo(type)) {
    std::ostringstream out;
    out << stream.rdbuf();
    *exception_info = out.str();
  }
  *log = stream.str();

  return true;
}

const char* GetSubjectTag(const std::string& type) {
  static const CrashLogHeaderMap kTags = {
      {"data_app_native_crash", "native app crash"},
      {"system_app_anr", "ANR"},
      {"data_app_anr", "app ANR"},
      {"system_server_watchdog", "system server watchdog"}};

  const auto it = kTags.find(type);
  return it == kTags.cend() ? nullptr : it->second.c_str();
}

bool IsSilentReport(const std::string& type) {
  return type == "system_app_wtf" || type == "system_server_wtf";
}

std::string GetCrashLogHeader(const CrashLogHeaderMap& map, const char* key) {
  const auto it = map.find(key);
  return it == map.end() ? "unknown" : it->second;
}

pid_t CreateRandomPID() {
  const auto now = base::TimeTicks::Now();
  return (now - ToSeconds(now)).InMicroseconds();
}

std::vector<std::pair<std::string, std::string>> ListBasicARCRelatedMetadata(
    const std::string& process, const std::string& crash_type) {
  std::vector<std::pair<std::string, std::string>> metadata;
  metadata.emplace_back(arc_util::kProductField, arc_util::kArcProduct);
  metadata.emplace_back(arc_util::kProcessField, process);
  metadata.emplace_back(arc_util::kCrashTypeField, crash_type);
  return metadata;
}

std::vector<std::pair<std::string, std::string>> ListMetadataForBuildProperty(
    const BuildProperty& build_property) {
  std::vector<std::pair<std::string, std::string>> metadata;
  metadata.emplace_back(kArcVersionField, build_property.fingerprint);
  metadata.emplace_back(kAndroidVersionField,
                        GetVersionFromFingerprint(build_property.fingerprint)
                            .value_or(kUnknownValue));
  metadata.emplace_back(kDeviceField, build_property.device);
  metadata.emplace_back(kBoardField, build_property.board);
  metadata.emplace_back(kCpuAbiField, build_property.cpu_abi);
  return metadata;
}

bool GetChromeVersion(std::string* version) {
  base::FilePath chrome_metadata_path =
      paths::Get(kChromeDirectory).Append("metadata.json");
  if (std::optional<std::string> version_maybe =
          util::ExtractChromeVersionFromMetadata(chrome_metadata_path);
      version_maybe) {
    *version = *version_maybe;
    return true;
  }
  return false;
}

std::string GetProductVersion() {
  std::string version;
  return GetChromeVersion(&version) ? version : kUnknownValue;
}

std::string FormatDuration(base::TimeDelta delta) {
  constexpr int64_t kSecondsPerMinute = 60;
  constexpr int64_t kSecondsPerHour = 60 * kSecondsPerMinute;
  constexpr int64_t kSecondsPerDay = 24 * kSecondsPerHour;

  std::ostringstream out;

  int64_t seconds = delta.InSeconds();
  if (seconds < 0) {
    out << "negative ";
    seconds = -seconds;
  }

  const auto days = seconds / kSecondsPerDay;
  seconds %= kSecondsPerDay;
  const auto hours = seconds / kSecondsPerHour;
  seconds %= kSecondsPerHour;
  const auto minutes = seconds / kSecondsPerMinute;
  seconds %= kSecondsPerMinute;

  if (days > 0)
    out << days << "d ";
  if (days > 0 || hours > 0)
    out << hours << "h ";
  if (days > 0 || hours > 0 || minutes > 0)
    out << minutes << "min ";

  out << seconds << 's';
  return out.str();
}

bool GetArcContainerUptime(
    org::chromium::SessionManagerInterfaceProxyInterface* session_manager_proxy,
    base::TimeDelta* uptime,
    base::TickClock* test_clock) {
  DCHECK(uptime);

  int64_t start_time = 0;
  brillo::ErrorPtr error;
  if (!session_manager_proxy->GetArcStartTimeTicks(&start_time, &error)) {
    LOG(ERROR) << "Failed to get ARC uptime: "
               << (error ? error->GetMessage() : "unknown error");
    return false;
  }

  auto end_time = test_clock ? test_clock->NowTicks() : base::TimeTicks::Now();
  *uptime = end_time - base::TimeTicks::FromInternalValue(start_time);
  return true;
}

}  // namespace arc_util
