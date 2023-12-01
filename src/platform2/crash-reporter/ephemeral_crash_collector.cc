// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/ephemeral_crash_collector.h"

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/process/process.h>

#include <string>

#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

EphemeralCrashCollector::EphemeralCrashCollector()
    : CrashCollector("ephemeral_crash_collector"),
      early_(false),
      source_directories_({base::FilePath(paths::kSystemRunCrashDirectory)}) {}

void EphemeralCrashCollector::Initialize(bool preserve_across_clobber) {
  // For preserving crash reports across clobbers, the consent file may not be
  // available. Instead, collect the crashes into the encrypted reboot vault
  // directory and let crash-sender decide how to deal with these reports.
  if (preserve_across_clobber) {
    system_crash_path_ =
        base::FilePath(paths::kEncryptedRebootVaultCrashDirectory);
    skip_consent_ = true;
    crash_directory_selection_method_ = kAlwaysUseSystemCrashDirectory;
  } else {
    // In case of powerwash, there is a chance that the powerwash was a result
    // of failure to mount the partition: in such situations, we may have crash
    // reports in the reboot vault to collect. Allow the meta collector to
    // collect such reports into /var/spool. Once OOBE is complete, depending
    // on user consent, either throw away these reports or send them.
    if (!base::PathExists(paths::Get(paths::kOobeCompletePath))) {
      // TODO(crbug/1039378): Remove this log once we have test failures that
      // ran with it.
      LOG(INFO) << "OOBE path doesn't exist. Integration tests running? "
                << std::boolalpha << util::IsCrashTestInProgress()
                << " Mock consent? " << std::boolalpha
                << util::HasMockConsent();
      skip_consent_ = true;
    }
    source_directories_.push_back(
        base::FilePath(paths::kEncryptedRebootVaultCrashDirectory));
  }

  // Disable early mode.
  CrashCollector::Initialize(false /* early */);
}

bool EphemeralCrashCollector::Collect() {
#if USE_DIRENCRYPTION
  // Join the session keyring, if one exists.
  util::JoinSessionKeyring();
#endif  // USE_DIRENCRYPTION

  for (auto& dir : source_directories_) {
    base::FileEnumerator source_directory_enumerator(
        dir, false /* recursive */, base::FileEnumerator::FILES);

    LOG(INFO) << "Examining " << dir << " for crashes";

    for (auto source_path = source_directory_enumerator.Next();
         !source_path.empty();
         source_path = source_directory_enumerator.Next()) {
      // Get crash directory to put logs in.
      base::FilePath destination_directory;

      // If the crash reporter directory is already fully occupied, then exit.
      if (!GetCreatedCrashDirectoryByEuid(0, &destination_directory, nullptr))
        break;

      base::FilePath destination_path =
          destination_directory.Append(source_path.BaseName());
      LOG(INFO) << "Copying early crash to: " << destination_path.value();

      if (!base::Move(source_path, destination_path)) {
        PLOG(WARNING) << "Unable to copy " << source_path.value();
        continue;
      }
    }
  }

  // Cleanup crash directory.
  for (auto& dir : source_directories_)
    base::DeletePathRecursively(dir);

  return true;
}
