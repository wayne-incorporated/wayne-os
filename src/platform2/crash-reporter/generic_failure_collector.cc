// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/generic_failure_collector.h"

#include <memory>
#include <optional>
#include <string>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "base/check.h"
#include "base/files/file_path.h"
#include "crash-reporter/constants.h"
#include "crash-reporter/util.h"

namespace {
const char kSignatureKey[] = "sig";
}  // namespace

using base::FilePath;
using base::StringPrintf;

const char* const GenericFailureCollector::kAuthFailure = "auth-failure";
const char* const GenericFailureCollector::kCryptohome = "cryptohome";
const char* const GenericFailureCollector::kSuspendFailure = "suspend-failure";
const char* const GenericFailureCollector::kServiceFailure = "service-failure";
const char* const GenericFailureCollector::kArcServiceFailure =
    "arc-service-failure";
const char* const GenericFailureCollector::kModemFailure = "cellular-failure";
const char* const GenericFailureCollector::kGuestOomEvent = "guest-oom-event";
const char* const GenericFailureCollector::kHermesFailure = "hermes_failure";

GenericFailureCollector::GenericFailureCollector()
    : CrashCollector("generic_failure"), failure_report_path_("/dev/stdin") {}

GenericFailureCollector::~GenericFailureCollector() {}

bool GenericFailureCollector::LoadGenericFailure(std::string* content,
                                                 std::string* signature) {
  FilePath failure_report_path(failure_report_path_.c_str());
  if (!base::ReadFileToString(failure_report_path, content)) {
    LOG(ERROR) << "Could not open " << failure_report_path.value();
    return false;
  }

  std::string::size_type end_position = content->find('\n');
  if (end_position == std::string::npos) {
    LOG(ERROR) << "unexpected generic failure format";
    return false;
  }
  *signature = content->substr(0, end_position);
  return true;
}

bool GenericFailureCollector::CollectFull(const std::string& exec_name,
                                          const std::string& log_key_name,
                                          std::optional<int> weight,
                                          bool use_log_conf_file) {
  LOG(INFO) << "Processing generic failure";

  std::string generic_failure;
  std::string failure_signature;
  if (!LoadGenericFailure(&generic_failure, &failure_signature)) {
    return true;
  }

  FilePath crash_directory;
  if (!GetCreatedCrashDirectoryByEuid(constants::kRootUid, &crash_directory,
                                      nullptr)) {
    return true;
  }

  std::string dump_basename = FormatDumpBasename(exec_name, time(nullptr), 0);
  FilePath log_path = GetCrashPath(crash_directory, dump_basename, "log");
  FilePath meta_path = GetCrashPath(crash_directory, dump_basename, "meta");
  if (weight) {
    AddCrashMetaUploadData("weight", StringPrintf("%d", *weight));
  }

  AddCrashMetaData(kSignatureKey, failure_signature);

  bool result = use_log_conf_file
                    ? GetLogContents(log_config_path_, log_key_name, log_path)
                    : WriteLogContents(generic_failure, log_path);

  if (result) {
    FinishCrash(meta_path, exec_name, log_path.BaseName().value());
  }

  return true;
}

// static
CollectorInfo GenericFailureCollector::GetHandlerInfo(
    const HandlerInfoOptions& options) {
  auto generic_failure_collector = std::make_shared<GenericFailureCollector>();
  return {
      .collector = generic_failure_collector,
      .handlers = {
          {
              .should_handle = options.suspend_failure,
              .cb = base::BindRepeating(
                  &GenericFailureCollector::CollectWithWeight,
                  generic_failure_collector, kSuspendFailure,
                  util::GetSuspendFailureWeight()),
          },
          {
              .should_handle = options.auth_failure,
              .cb =
                  base::BindRepeating(&GenericFailureCollector::Collect,
                                      generic_failure_collector, kAuthFailure),
          },
          {
              .should_handle = options.modem_failure,
              .cb = base::BindRepeating(
                  &GenericFailureCollector::CollectWithWeight,
                  generic_failure_collector, kModemFailure, options.weight),
          },
          {
              .should_handle = options.hermes_failure,
              .cb = base::BindRepeating(
                  &GenericFailureCollector::CollectWithWeight,
                  generic_failure_collector, kHermesFailure, options.weight),
          },
          {
              .should_handle = !options.arc_service_failure.empty(),
              .cb = base::BindRepeating(
                  &GenericFailureCollector::CollectFull,
                  generic_failure_collector,
                  StringPrintf("%s-%s", kArcServiceFailure,
                               options.arc_service_failure.c_str()),
                  kArcServiceFailure, util::GetServiceFailureWeight(),
                  /*use_log_conf_file=*/true),
          },
          {
              .should_handle = !options.service_failure.empty(),
              .cb = base::BindRepeating(
                  &GenericFailureCollector::CollectFull,
                  generic_failure_collector,
                  StringPrintf("%s-%s", kServiceFailure,
                               options.service_failure.c_str()),
                  kServiceFailure, util::GetServiceFailureWeight(),
                  /*use_log_conf_file=*/true),
          },
          {.should_handle = options.guest_oom_event,
           .should_check_appsync = true,
           .cb = base::BindRepeating(&GenericFailureCollector::CollectFull,
                                     generic_failure_collector, kGuestOomEvent,
                                     "", util::GetOomEventWeight(),
                                     /*use_log_conf_file=*/false)},
          {
              .should_handle = options.recovery_failure,
              .cb = base::BindRepeating(
                  &GenericFailureCollector::CollectWithWeight,
                  generic_failure_collector, kCryptohome,
                  util::GetRecoveryFailureWeight()),
          },
      }};
}
