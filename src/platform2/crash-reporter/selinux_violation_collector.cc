// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/selinux_violation_collector.h"

#include <map>
#include <memory>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/util.h"

namespace {
constexpr char kExecName[] = "selinux-violation";
constexpr char kSignatureKey[] = "sig";
// Truncate values of key=value strings longer than this
constexpr size_t kMaxValueLen = 128;
}  // namespace

using base::FilePath;
using base::StringPrintf;

SELinuxViolationCollector::SELinuxViolationCollector()
    : CrashCollector("selinux"), violation_report_path_("/dev/stdin") {}

SELinuxViolationCollector::~SELinuxViolationCollector() {}

bool SELinuxViolationCollector::LoadSELinuxViolation(
    std::string* content,
    std::string* signature,
    std::map<std::string, std::string>* extra_metadata) {
  std::string violation_report;
  if (!base::ReadFileToString(violation_report_path_, &violation_report)) {
    PLOG(ERROR) << "Could not open " << violation_report_path_.value();
    return false;
  }

  // Report format
  // First line:  signature
  // Second line: parsed metadata key\x01value\x02key\x01value\x02
  // Third+ line: content

  std::string::size_type signature_end_position = violation_report.find('\n');
  *signature = violation_report.substr(0, signature_end_position);

  violation_report = violation_report.substr(signature_end_position + 1);
  std::string::size_type metadata_end_position = violation_report.find('\n');
  *content = violation_report.substr(metadata_end_position + 1);

  base::StringPairs kvpairs;
  if (!base::SplitStringIntoKeyValuePairs(
          violation_report.substr(0, metadata_end_position), '\x01', '\x02',
          &kvpairs)) {
    return false;
  }

  for (const auto& kvpair : kvpairs) {
    extra_metadata->emplace(kvpair.first, kvpair.second);
  }

  return !signature->empty();
}

// Extract the value of the given key from the selinux log.
// Params:
//   log: The string with the selinux message
//   key: The key to search for
//   has_quotes: True iff the value is surrounded by quotes; e.g. comm="cros"
//   value: Output parameter.
// Return true if the key was present, or false otherwise.
bool GetValueFromLog(const std::string& log,
                     const std::string& key,
                     bool has_quotes,
                     std::string* value) {
  std::string full_key = key + "=";
  if (has_quotes) {
    full_key += "\"";
  }
  std::string::size_type key_start = log.find(full_key);
  if (key_start != std::string::npos) {
    std::string::size_type value_start = key_start + full_key.size();
    char end_char = has_quotes ? '"' : ' ';
    std::string::size_type value_end = log.find(end_char, value_start);
    std::string::size_type substr_len = value_end - value_start;
    substr_len = substr_len > kMaxValueLen ? kMaxValueLen : substr_len;
    *value = log.substr(value_start, substr_len);
    return true;
  }
  return false;
}

bool SELinuxViolationCollector::Collect(int32_t weight) {
  LOG(INFO) << "Processing selinux violation";

  if (weight != 1) {
    AddCrashMetaUploadData("weight", StringPrintf("%d", weight));
  }

  std::string violation_signature;
  std::string content;
  std::map<std::string, std::string> extra_metadata;
  if (!LoadSELinuxViolation(&content, &violation_signature, &extra_metadata))
    return true;

  FilePath crash_directory;
  if (!GetCreatedCrashDirectoryByEuid(constants::kRootUid, &crash_directory,
                                      nullptr))
    return true;

  // Give crash files more unique names by taking the "comm" identifier
  // (if one is present) and adding it to the "selinux-violation" prefix.
  std::string name_prefix = kExecName;

  std::string comm;
  if (GetValueFromLog(content, "comm", /*has_quotes=*/true, &comm)) {
    name_prefix += "_" + comm;
  }

  std::string pid_str;
  int pid = 0;
  if (GetValueFromLog(content, "pid", /*has_quotes=*/false, &pid_str)) {
    if (!base::StringToInt(pid_str, &pid)) {
      // Fall back to a pid of 0 on any errors.
      pid = 0;
    }
  }

  std::string dump_basename =
      FormatDumpBasename(name_prefix, time(nullptr), pid);
  FilePath meta_path = GetCrashPath(crash_directory, dump_basename, "meta");
  FilePath log_path = GetCrashPath(crash_directory, dump_basename, "log");

  if (WriteNewFile(log_path, content) != static_cast<int>(content.length())) {
    PLOG(WARNING) << "Failed to write audit message to " << log_path.value();
    return true;
  }

  AddCrashMetaData(kSignatureKey, violation_signature);

  for (const auto& metadata : extra_metadata)
    AddCrashMetaUploadData(metadata.first, metadata.second);

  FinishCrash(meta_path, kExecName, log_path.BaseName().value());

  return true;
}

// static
CollectorInfo SELinuxViolationCollector::GetHandlerInfo(bool selinux_violation,
                                                        int32_t weight) {
  auto selinux_violation_collector =
      std::make_shared<SELinuxViolationCollector>();
  return {.collector = selinux_violation_collector,
          .handlers = {{
              .should_handle = selinux_violation,
              .cb = base::BindRepeating(&SELinuxViolationCollector::Collect,
                                        selinux_violation_collector, weight),
          }}};
}
