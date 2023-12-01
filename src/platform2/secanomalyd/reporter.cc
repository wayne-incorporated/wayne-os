// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secanomalyd/reporter.h"

#include <optional>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/process/process.h>
#include <crypto/sha2.h>
#include <vboot/crossystem.h>

#include "secanomalyd/mounts.h"
#include "secanomalyd/processes.h"

namespace secanomalyd {

namespace {

constexpr size_t kHashPrefixLengthInBytes = 5u;

constexpr char kRootPathReplacement[] = "slashroot";
constexpr char kCrashReporterPath[] = "/sbin/crash_reporter";
constexpr char kSecurityAnomalyFlag[] = "--security_anomaly";
constexpr char kWeightFlag[] = "--weight";

}  // namespace

bool ShouldReport(bool report_in_dev_mode) {
  // Reporting should only happen when booted in Verified mode and not running
  // a developer image, unless explicitly instructed otherwise.
  return ::VbGetSystemPropertyInt("cros_debug") == 0 || report_in_dev_mode;
}

std::string GenerateSignature(const MountEntryMap& wx_mounts) {
  std::vector<std::string> dests;

  for (const auto& p : wx_mounts) {
    dests.emplace_back(p.first.value());
  }

  std::string signature;
  // Use the first path as a visible sentinel for the signature.
  // If the anomalous mount is on '/', replace the destination path with a
  // default value so that the signature doesn't have consecutive dashes.
  if (dests[0] != "/") {
    base::ReplaceChars(dests[0], "/", "-", &signature);
  } else {
    signature = kRootPathReplacement;
  }

  // Hash the string resulting from joining all mount destinations separated
  // by newlines. Take the first five bytes and use that to complete the
  // signature.
  std::vector<uint8_t> prefix(kHashPrefixLengthInBytes);
  crypto::SHA256HashString(base::JoinString(dests, "\n"), prefix.data(),
                           prefix.size());
  base::StrAppend(&signature, {"-", base::HexEncode(prefix)});

  return signature;
}

MaybeReport GenerateAnomalousSystemReport(const MountEntryMap& wx_mounts,
                                          const MaybeMountEntries& all_mounts,
                                          const MaybeProcEntries& all_procs) {
  // First line: signature
  // Second line: metadata
  //    signals: wx-mount|root-proc|non-vb-proc
  //    dest: /usr/local, e.g.
  // Third+ line: content

  // We need at least one anomalous condition to generate the report signature.
  if (wx_mounts.empty()) {
    return std::nullopt;
  }

  std::vector<std::string> lines;

  // Generate signature.
  lines.emplace_back(GenerateSignature(wx_mounts));

  // Generate metadata.
  base::FilePath dest = wx_mounts.begin()->first;
  std::string metadata;
  // Metadata are a set of key-value pairs where keys and values are separated
  // by \x01 and pairs are separated by \x02:
  // 'signals\x01wx-mount\x02dest\x01/usr/local'
  // Right now we only support listing which anomalies triggered the upload of
  // this report, and signalling which specific anomaly was used for the
  // signature.
  base::StrAppend(&metadata,
                  {"signals\x01wx-mount", "\x02", "dest\x01", dest.value()});
  lines.emplace_back(metadata);

  // List anomalous conditions.
  lines.emplace_back("=== Anomalous conditions ===");
  for (const auto& tuple : wx_mounts) {
    lines.push_back(tuple.second.FullDescription());
  }

  lines.emplace_back("=== Mounts ===");
  if (all_mounts) {
    // List mounts.
    for (const auto& mount_entry : all_mounts.value()) {
      lines.push_back(mount_entry.FullDescription());
    }
  } else {
    lines.emplace_back("Could not obtain mounts");
  }

  lines.emplace_back("=== Processes ===");
  if (all_procs) {
    // List processes.
    for (const auto& proc_entry : all_procs.value()) {
      lines.emplace_back(proc_entry.args());
    }
  } else {
    lines.emplace_back("Could not obtain processes");
  }

  // Ensure reports have a trailing newline. Trailing newlines make reports
  // easier to read in a terminal.
  lines.emplace_back("");
  return MaybeReport(base::JoinString(lines, "\n"));
}

bool SendReport(base::StringPiece report,
                brillo::Process* crash_reporter,
                int weight,
                bool report_in_dev_mode) {
  if (!ShouldReport(report_in_dev_mode)) {
    VLOG(1) << "Not in Verified mode, not reporting";
    return true;
  }

  VLOG(1) << "secanomalyd invoking crash_reporter";

  crash_reporter->AddArg(kCrashReporterPath);
  crash_reporter->AddArg(kSecurityAnomalyFlag);
  crash_reporter->AddArg(base::StringPrintf("%s=%d", kWeightFlag, weight));

  crash_reporter->RedirectUsingPipe(STDIN_FILENO, true /*is_input*/);

  if (!crash_reporter->Start()) {
    LOG(ERROR) << "Failed to start crash reporting process";
    return false;
  }

  int stdin_fd = crash_reporter->GetPipe(STDIN_FILENO);
  if (stdin_fd < 0) {
    LOG(ERROR) << "Failed to get stdin pipe for crash reporting process";
    return false;
  }

  {
    base::ScopedFD stdin(stdin_fd);

    if (!base::WriteFileDescriptor(stdin_fd, report)) {
      LOG(ERROR) << "Failed to write report to crash reporting process' stdin";
      return false;
    }
  }

  // |crash_reporter| returns 0 on success.
  return crash_reporter->Wait() == 0;
}

bool ReportAnomalousSystem(const MountEntryMap& wx_mounts,
                           int weight,
                           bool report_in_dev_mode) {
  MaybeMountEntries maybe_mounts = ReadMounts(MountFilter::kUploadableOnly);
  MaybeProcEntries maybe_procs =
      ReadProcesses(ProcessFilter::kInitPidNamespaceOnly);

  MaybeReport anomaly_report =
      GenerateAnomalousSystemReport(wx_mounts, maybe_mounts, maybe_procs);

  if (!anomaly_report) {
    LOG(ERROR) << "Failed to generate anomalous system report";
    return false;
  }

  brillo::ProcessImpl crash_reporter;
  if (!SendReport(anomaly_report.value(), &crash_reporter, weight,
                  report_in_dev_mode)) {
    LOG(ERROR) << "Failed to send anomalous system report";
    return false;
  }

  return true;
}

}  // namespace secanomalyd
