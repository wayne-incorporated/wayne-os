// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cfm-dfu-notification/dfu_log_notification.h"

#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/values.h>
#include <string>

namespace {
// Updater Notification constants.
const char kNameParameter[] = "name";
const char kSuccessParameter[] = "success";
const char kTimeoutSecondsParameter[] = "timeoutSec";
const char kPercentDoneParameter[] = "perecentDone";
}  // namespace

DfuLogNotification::DfuLogNotification(const std::string& device_name)
    : device_name_(device_name) {}

void DfuLogNotification::NotifyStartUpdate(unsigned int timeout_seconds) {
  base::Value::Dict start_parameters;
  start_parameters.Set(kNameParameter, device_name_);
  start_parameters.Set(kTimeoutSecondsParameter,
                       static_cast<int>(timeout_seconds));

  std::string start_parameters_json;
  if (base::JSONWriter::Write(start_parameters, &start_parameters_json)) {
    LOG(INFO) << "$#StartUpdate$#" << start_parameters_json;
  } else {
    LOG(ERROR) << "Unable to write start update for " << device_name_
               << ", partial "
                  "output: "
               << start_parameters_json;
  }
}

void DfuLogNotification::NotifyEndUpdate(bool success) {
  base::Value::Dict end_parameters;
  end_parameters.Set(kNameParameter, device_name_);
  end_parameters.Set(kSuccessParameter, success);

  std::string end_parameters_json;
  if (base::JSONWriter::Write(end_parameters, &end_parameters_json)) {
    LOG(INFO) << "$#EndUpdate$#" << end_parameters_json;
  } else {
    LOG(ERROR) << "Unable to write end update for " << device_name_
               << ", partial output:" << end_parameters_json;
  }
}

void DfuLogNotification::NotifyUpdateProgress(float percent_done) {
  base::Value::Dict progress_parameters;
  progress_parameters.Set(kNameParameter, device_name_);
  progress_parameters.Set(kPercentDoneParameter, percent_done);

  std::string progress_parameters_json;
  if (base::JSONWriter::Write(progress_parameters, &progress_parameters_json)) {
    LOG(INFO) << "$#UpdateProgress$#" << progress_parameters_json;
  } else {
    LOG(ERROR) << "Unable to write end update for " << device_name_
               << ", partial output: " << progress_parameters_json;
  }
}
