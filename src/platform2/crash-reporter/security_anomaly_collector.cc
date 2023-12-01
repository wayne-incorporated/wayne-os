// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/security_anomaly_collector.h"

#include <memory>
#include <string>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

#include "crash-reporter/constants.h"

namespace {
constexpr char kExecName[] = "security-anomaly";
constexpr char kMetadataKeyPrefix[] = "security_anomaly_";
constexpr char kSignatureKey[] = "sig";
}  // namespace

SecurityAnomalyCollector::SecurityAnomalyCollector()
    : CrashCollector("security_anomaly_collector"),
      anomaly_report_path_("/dev/stdin") {}

bool SecurityAnomalyCollector::LoadSecurityAnomaly(
    std::string* content,
    std::string* signature,
    std::map<std::string, std::string>* extra_metadata) {
  std::string anomaly_report;
  if (!base::ReadFileToString(anomaly_report_path_, &anomaly_report)) {
    PLOG(ERROR) << "Could not open " << anomaly_report_path_.value();
    return false;
  }

  // Report format
  // First line:  signature
  // Second line: parsed metadata key\x01value\x02key\x01value\x02
  // Third+ line: content

  std::string::size_type signature_end_position = anomaly_report.find('\n');
  if (signature_end_position == std::string::npos) {
    return false;
  }
  *signature = anomaly_report.substr(0, signature_end_position);

  anomaly_report = anomaly_report.substr(signature_end_position + 1);
  std::string::size_type metadata_end_position = anomaly_report.find('\n');
  if (metadata_end_position == std::string::npos) {
    return false;
  }
  *content = anomaly_report.substr(metadata_end_position + 1);

  base::StringPairs kvpairs;
  if (!base::SplitStringIntoKeyValuePairs(
          anomaly_report.substr(0, metadata_end_position), '\x01', '\x02',
          &kvpairs)) {
    return false;
  }

  for (const auto& kvpair : kvpairs) {
    extra_metadata->emplace(kMetadataKeyPrefix + kvpair.first, kvpair.second);
  }

  return !signature->empty();
}

bool SecurityAnomalyCollector::Collect(int32_t weight) {
  LOG(INFO) << "Processing security anomaly";

  if (weight != 1) {
    AddCrashMetaUploadData("weight", base::NumberToString(weight));
  }

  std::string signature;
  std::string content;
  std::map<std::string, std::string> extra_metadata;
  if (!LoadSecurityAnomaly(&content, &signature, &extra_metadata))
    return false;

  base::FilePath crash_directory;
  if (!GetCreatedCrashDirectoryByEuid(constants::kRootUid, &crash_directory,
                                      nullptr))
    return false;

  std::string dump_basename = FormatDumpBasename(kExecName, time(nullptr), 0);
  base::FilePath meta_path =
      GetCrashPath(crash_directory, dump_basename, "meta");
  base::FilePath log_path = GetCrashPath(crash_directory, dump_basename, "log");

  base::StringPiece file_content(content);
  if (WriteNewFile(log_path, file_content) !=
      static_cast<int>(file_content.length())) {
    PLOG(WARNING) << "Failed to write security anomaly to " << log_path.value();
    return false;
  }

  AddCrashMetaData(kSignatureKey, signature);

  for (const auto& metadata : extra_metadata)
    AddCrashMetaUploadData(metadata.first, metadata.second);

  FinishCrash(meta_path, kExecName, log_path.BaseName().value());

  return true;
}

// static
CollectorInfo SecurityAnomalyCollector::GetHandlerInfo(int32_t weight,
                                                       bool security_anomaly) {
  auto security_anomaly_collector =
      std::make_shared<SecurityAnomalyCollector>();
  return {.collector = security_anomaly_collector,
          .handlers = {{
              .should_handle = security_anomaly,
              .cb = base::BindRepeating(&SecurityAnomalyCollector::Collect,
                                        security_anomaly_collector, weight),
          }}};
}
