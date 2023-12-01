// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/clobber_state_collector.h"

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/util.h"

namespace {
constexpr size_t kMaxSignature = 256;
constexpr size_t kMaxSignatureSearch = 4096;
constexpr const char kTmpfilesLogPath[] = "/run/tmpfiles.log";
constexpr const char kClobberStateName[] = "clobber-state";

std::string filter_signature(const std::vector<std::string>& lines) {
  static constexpr const char* const known_issues[] = {
      // This is associated with an EXT4-fs error in htree_dirblock_to_tree:
      // "Directory block failed checksum"
      "Bad message",
      // This typically indicates the storage media is failing.
      "Input/output error",
      // The disk is too full to create the necessary directories on stateful.
      "No space left on device",
      // Particularly bad filesystem corruption results in it being remounted
      // read only.
      "Read-only file system",
      // This is associated with an EXT4-fs error in ext4_xattr_block_get:
      // "corrupted xattr block ####"
      "Structure needs cleaning",
  };

  for (const std::string& line : lines) {
    // There are some duplicate entries on purpose because of ARCVM not
    // being present on all systems. For example:
    //
    //   /usr/lib/tmpfiles.d/vm_tools.conf:35: Duplicate line for path \
    //     "/run/arc/sdcard", ignoring.
    //
    // Skip these lines because they did not cause the clobber.
    if (!base::EndsWith(line, "ignoring.")) {
      for (auto known_issue : known_issues) {
        if (base::EndsWith(line, known_issue)) {
          return known_issue;
        }
      }
      return line.substr(0, kMaxSignature);
    }
  }
  // We should never get here, but if we do, set a consistent signature.
  return kNoErrorLogged;
}

}  // namespace

ClobberStateCollector::ClobberStateCollector()
    : CrashCollector("clobber_state_collector"),
      tmpfiles_log_(kTmpfilesLogPath) {}

bool ClobberStateCollector::Collect() {
  std::string exec_name(kClobberStateName);
  std::string dump_basename = FormatDumpBasename(exec_name, time(nullptr), 0);

  base::FilePath crash_directory;
  if (!GetCreatedCrashDirectoryByEuid(constants::kRootUid, &crash_directory,
                                      nullptr)) {
    return false;
  }

  // Use the first line or first 1024 bytes of the tmpfiles log as the
  // signature with the exec_name as a fall back.
  std::string tmpfiles_log;
  if (!base::ReadFileToStringWithMaxSize(tmpfiles_log_, &tmpfiles_log,
                                         kMaxSignatureSearch) &&
      tmpfiles_log.empty()) {
    PLOG(ERROR) << "Failed to read '" << kTmpfilesLogPath << "'";
  }
  util::RedactDigests(&tmpfiles_log);
  auto lines = base::SplitString(tmpfiles_log, "\n", base::TRIM_WHITESPACE,
                                 base::SPLIT_WANT_NONEMPTY);
  if (lines.empty()) {
    // Fall back to the exec name as the crash signature.
    AddCrashMetaData("sig", exec_name);
  } else {
    AddCrashMetaData("sig", filter_signature(lines));
  }

  base::FilePath log_path = GetCrashPath(crash_directory, dump_basename, "log");
  base::FilePath meta_path =
      GetCrashPath(crash_directory, dump_basename, "meta");

  bool result = GetLogContents(log_config_path_, exec_name, log_path);
  if (result) {
    FinishCrash(meta_path, exec_name, log_path.BaseName().value());
  }

  return result;
}

// static
CollectorInfo ClobberStateCollector::GetHandlerInfo(bool clobber_state) {
  auto clobber_state_collector = std::make_shared<ClobberStateCollector>();
  return {
      .collector = clobber_state_collector,
      .handlers = {{
          .should_handle = clobber_state,
          .cb = base::BindRepeating(&ClobberStateCollector::Collect,
                                    clobber_state_collector),
      }},
  };
}
