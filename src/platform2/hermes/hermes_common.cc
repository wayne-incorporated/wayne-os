// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "hermes/hermes_common.h"

#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>

namespace hermes {

std::string GetTrailingChars(const std::string& pii, int num_chars) {
  DCHECK_GE(num_chars, 0);
  if (num_chars > pii.length())
    return pii;
  return pii.substr(pii.length() - num_chars);
}

std::string GetObjectPathForLog(const dbus::ObjectPath& dbus_path) {
  const std::string kPrefix = "dbus_path(Last 3 chars): ";
  const int kDbusPathPrintLen = 3;
  return kPrefix + GetTrailingChars(dbus_path.value(), kDbusPathPrintLen);
}

void IgnoreErrorRunClosure(base::OnceCallback<void()> cb, int err) {
  VLOG(2) << "Modem message processed with code:" << err;
  std::move(cb).Run();
}

void PrintMsgProcessingResult(int err) {
  VLOG(2) << "Modem processed message processed with code:" << err;
}

void RunNextStep(
    base::OnceCallback<void(base::OnceCallback<void(int)>)> next_step,
    base::OnceCallback<void(int)> cb,
    int err) {
  VLOG(2) << "Modem message processed with code:" << err;
  if (err) {
    std::move(cb).Run(err);
    return;
  }
  std::move(next_step).Run(std::move(cb));
}

const char* GetDBusError(int err) {
  switch (err) {
    case kModemMessageProcessingError:
      return kErrorModemMessageProcessing;
    case kModemManagerError:
      return kErrorUnexpectedModemManagerState;
    default:
      return kErrorUnknown;
  }
}

}  // namespace hermes
