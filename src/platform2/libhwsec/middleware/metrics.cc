// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/middleware/metrics.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_split.h>
#include <metrics/metrics_library.h>

#include "libhwsec/error/tpm_retry_action.h"
#include "libhwsec/status.h"

namespace {
constexpr char kHwsecMetricsPrefix[] = "Platform.Libhwsec.RetryAction";
}  // namespace

namespace hwsec {

bool Metrics::SendFuncResultToUMA(const std::string& func_name,
                                  const Status& status) {
  TPMRetryAction action;
  if (status.ok()) {
    action = TPMRetryAction::kNone;
  } else {
    action = status->ToTPMRetryAction();
  }

  std::vector<std::string> func_splits = base::SplitString(
      func_name, "::", base::WhitespaceHandling::TRIM_WHITESPACE,
      base::SplitResult::SPLIT_WANT_NONEMPTY);

  std::string current_uma = kHwsecMetricsPrefix;
  bool result = true;
  result &= metrics_->SendEnumToUMA(current_uma, action);

  for (const std::string& split : func_splits) {
    // Ignore the "hwsec" namespace.
    if (split == "hwsec") {
      continue;
    }

    current_uma += ".";
    current_uma += split;
    result &= metrics_->SendEnumToUMA(current_uma, action);
  }

  return result;
}

}  // namespace hwsec
