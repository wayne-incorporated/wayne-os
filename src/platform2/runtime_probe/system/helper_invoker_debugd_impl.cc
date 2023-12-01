// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/system/helper_invoker_debugd_impl.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/errors/error.h>
#include <debugd/dbus-proxies.h>

#include "runtime_probe/system/context.h"
#include "runtime_probe/utils/pipe_utils.h"

namespace runtime_probe {

bool HelperInvokerDebugdImpl::Invoke(const ProbeFunction* probe_function,
                                     const std::string& probe_statement_str,
                                     std::string* result) const {
  base::ScopedFD result_fd{};
  base::ScopedFD error_fd{};
  brillo::ErrorPtr error;
  if (!Context::Get()->debugd_proxy()->EvaluateProbeFunction(
          probe_statement_str, logging::GetMinLogLevel(), &result_fd, &error_fd,
          &error)) {
    LOG(ERROR) << "Debugd::EvaluateProbeFunction failed: "
               << error->GetMessage();
    return false;
  }

  std::vector<std::string> out;
  bool res =
      ReadNonblockingPipeToString({result_fd.get(), error_fd.get()}, &out);
  if (out[1].size()) {
    LOG(INFO) << "Helper stderr:\n"
              << "^--------------------------------------------------------^\n"
              << out[1]
              << "$--------------------------------------------------------$";
  }
  if (!res) {
    LOG(ERROR) << "Cannot read result from helper";
    return false;
  }
  *result = std::move(out[0]);
  return true;
}

}  // namespace runtime_probe
