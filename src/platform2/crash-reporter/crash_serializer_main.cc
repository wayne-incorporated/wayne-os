// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>
#include <vector>

#include <stdlib.h>

#include <base/files/file.h>
#include <base/logging.h>
#include <base/time/default_clock.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "crash-reporter/crash_sender_base.h"
#include "crash-reporter/crash_sender_paths.h"
#include "crash-reporter/crash_sender_util.h"
#include "crash-reporter/crash_serializer.h"
#include "crash-reporter/paths.h"

// Default max size of protos in output.
// Defaults to 1MiB per
// https://developers.google.com/protocol-buffers/docs/techniques#large-data
// which says, "As a general rule of thumb, if you are dealing in messages
// larger than a megabyte each, it may be time to consider an alternate
// strategy."
constexpr int64_t kDefaultChunkSizeBytes = 1 << 20;
// Maximum allowable size of a proto in output (arbitrarily chosen).
constexpr int64_t kMaxChunkSizeBytes = 1 << 30;

int main(int argc, char* argv[]) {
  // Log to both stderr and syslog so that automated SSH connections can see
  // error output.
  brillo::OpenLog("crash_serializer", true);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  DEFINE_bool(fetch_coredumps, false,
              "If set, include coredumps in the serialized output");
  DEFINE_int64(chunk_size, kDefaultChunkSizeBytes,
               "Approximate maximum size of an individual proto message to "
               "write to stdout.");
  brillo::FlagHelper::Init(argc, argv, "ChromeOS Crash Sender");
  if (FLAGS_chunk_size < 0 || FLAGS_chunk_size > kMaxChunkSizeBytes) {
    LOG(ERROR) << "Invalid value for max chunk size: " << FLAGS_chunk_size;
    return EXIT_FAILURE;
  }

  crash_serializer::Serializer::Options options;
  auto clock = std::make_unique<base::DefaultClock>();
  options.fetch_coredumps = FLAGS_fetch_coredumps;
  options.max_proto_bytes = FLAGS_chunk_size;

  crash_serializer::Serializer serializer(std::move(clock), options);

  // Get all crashes.
  std::vector<base::FilePath> crash_directories;
  crash_directories = serializer.GetUserCrashDirectories();
  crash_directories.push_back(paths::Get(paths::kSystemCrashDirectory));
  crash_directories.push_back(paths::Get(paths::kFallbackUserCrashDirectory));

  std::vector<util::MetaFile> reports_to_send;

  // Pick the reports to serialize.
  base::File lock_file(serializer.AcquireLockFileOrDie());
  for (const auto& directory : crash_directories) {
    serializer.PickCrashFiles(directory, &reports_to_send);
  }
  lock_file.Close();

  // Actually serialize them.
  serializer.SerializeCrashes(reports_to_send);
}
