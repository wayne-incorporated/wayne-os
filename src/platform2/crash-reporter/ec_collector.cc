// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/ec_collector.h"

#include <string>

#include <base/base64.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/stringprintf.h>
#include <libec/ec_command.h>
#include <libec/ec_panicinfo.h>

#include "crash-reporter/util.h"

using base::FilePath;
using base::StringPiece;
using base::StringPrintf;

using brillo::ProcessImpl;

namespace {

const char kECDebugFSPath[] = "/sys/kernel/debug/cros_ec/";
const char kECPanicInfo[] = "panicinfo";
const char kECExecName[] = "embedded-controller";

}  // namespace

ECCollector::ECCollector()
    : CrashCollector("ec"), debugfs_path_(kECDebugFSPath) {}

ECCollector::~ECCollector() {}

bool ECCollector::Collect(bool use_saved_lsb) {
  SetUseSavedLsb(use_saved_lsb);

  char data[1024];
  int len;
  FilePath panicinfo_path = debugfs_path_.Append(kECPanicInfo);
  FilePath root_crash_directory;

  if (!base::PathExists(panicinfo_path)) {
    return false;
  }

  len = base::ReadFile(panicinfo_path, data, sizeof(data));

  if (len < 0) {
    PLOG(ERROR) << "Unable to open " << panicinfo_path.value();
    return false;
  }

  if (len <= PANIC_DATA_FLAGS_BYTE) {
    LOG(ERROR) << "EC panicinfo is too short (" << len << " bytes).";
    return false;
  }

  // Check if the EC crash has already been fetched before, in a previous AP
  // boot (EC sets this flag when the AP fetches the panic information).
  if (data[PANIC_DATA_FLAGS_BYTE] & PANIC_DATA_FLAG_OLD_HOSTCMD) {
    LOG(INFO) << "Stale EC crash: already fetched, not reporting.";
    return false;
  }

  LOG(INFO) << "Received crash notification from EC (handling)";

  if (!GetCreatedCrashDirectoryByEuid(0, &root_crash_directory, nullptr)) {
    return true;
  }

  base::span<uint8_t> sdata = base::make_span(reinterpret_cast<uint8_t*>(data),
                                              static_cast<size_t>(len));
  auto result = ec::ParsePanicInfo(sdata);
  std::string output;

  if (!result.has_value()) {
    LOG(ERROR) << "Failed to get valid eccrash. Error=" << result.error();
    return false;
  } else {
    output = result.value();
  }

  std::string dump_basename = FormatDumpBasename(kECExecName, time(nullptr), 0);
  FilePath ec_crash_path = root_crash_directory.Append(
      StringPrintf("%s.eccrash", dump_basename.c_str()));
  FilePath log_path = root_crash_directory.Append(
      StringPrintf("%s.log", dump_basename.c_str()));

  // We must use WriteNewFile instead of base::WriteFile as we
  // do not want to write with root access to a symlink that an attacker
  // might have created.
  if (WriteNewFile(ec_crash_path, output) != static_cast<int>(output.size())) {
    PLOG(ERROR) << "Failed to write EC dump to "
                << ec_crash_path.value().c_str();
    return true;
  }

  std::string signature = StringPrintf(
      "%s-%08X", kECExecName, util::HashString(StringPiece(data, len)));

  AddCrashMetaData("sig", signature);
  // Add EC info and AP version into log file.
  if (GetLogContents(log_config_path_, kECExecName, log_path)) {
    AddCrashMetaUploadFile("log", log_path.BaseName().value());
  }
  FinishCrash(root_crash_directory.Append(
                  StringPrintf("%s.meta", dump_basename.c_str())),
              kECExecName, ec_crash_path.BaseName().value());

  LOG(INFO) << "Stored EC crash to " << ec_crash_path.value();

  return true;
}
