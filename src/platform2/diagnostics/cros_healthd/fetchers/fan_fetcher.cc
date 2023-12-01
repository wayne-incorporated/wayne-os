// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/fan_fetcher.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/errors/error.h>
#include <re2/re2.h>

#include "debugd/dbus-proxies.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr auto kFanStalledRegex = R"(Fan \d+ stalled \(RPM: 65534\))";
constexpr auto kFanSpeedRegex = R"(Fan \d+ RPM: (\d+))";

}  // namespace

void FanFetcher::FetchFanInfo(FetchFanInfoCallback callback) {
  // Devices without a Google EC, and therefore ectool, cannot obtain fan info.
  if (!base::PathExists(context_->root_dir().Append(kRelativeCrosEcPath))) {
    LOG(INFO) << "Device does not have a Google EC.";
    std::move(callback).Run(mojom::FanResult::NewFanInfo({}));
    return;
  }

  context_->executor()->GetFanSpeed(
      base::BindOnce(&FanFetcher::HandleFanSpeedResponse,
                     weak_factory_.GetWeakPtr(), std::move(callback)));
}

void FanFetcher::HandleFanSpeedResponse(
    FetchFanInfoCallback callback, mojom::ExecutedProcessResultPtr result) {
  std::string err = result->err;
  int32_t return_code = result->return_code;
  if (!err.empty() || return_code != EXIT_SUCCESS) {
    std::move(callback).Run(mojom::FanResult::NewError(CreateAndLogProbeError(
        mojom::ErrorType::kSystemUtilityError,
        base::StringPrintf(
            "GetFanSpeed failed with return code: %d and error: %s",
            return_code, err.c_str()))));
    return;
  }

  std::vector<mojom::FanInfoPtr> fan_info;
  std::string output = result->out;
  std::vector<std::string> lines = base::SplitString(
      output, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const auto& line : lines) {
    if (RE2::FullMatch(line, kFanStalledRegex)) {
      fan_info.push_back(mojom::FanInfo::New(0));
      continue;
    }

    std::string regex_result;
    if (!RE2::FullMatch(line, kFanSpeedRegex, &regex_result)) {
      std::move(callback).Run(mojom::FanResult::NewError(
          CreateAndLogProbeError(mojom::ErrorType::kParseError,
                                 "Line does not match regex: " + line)));
      return;
    }

    uint32_t speed;
    if (base::StringToUint(regex_result, &speed)) {
      fan_info.push_back(mojom::FanInfo::New(speed));
    } else {
      std::move(callback).Run(mojom::FanResult::NewError(CreateAndLogProbeError(
          mojom::ErrorType::kParseError,
          "Failed to convert regex result to integer: " + regex_result)));
      return;
    }
  }

  std::move(callback).Run(mojom::FanResult::NewFanInfo(std::move(fan_info)));
}

}  // namespace diagnostics
