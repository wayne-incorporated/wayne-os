// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_SYSTEM_HELPER_INVOKER_DEBUGD_IMPL_H_
#define RUNTIME_PROBE_SYSTEM_HELPER_INVOKER_DEBUGD_IMPL_H_

#include "runtime_probe/system/context.h"
#include "runtime_probe/system/helper_invoker.h"

#include <string>

namespace runtime_probe {

class HelperInvokerDebugdImpl : public HelperInvoker {
  using HelperInvoker::HelperInvoker;

 public:
  // Invoke the helper replica via `debugd`'s D-Bus RPC.
  bool Invoke(const ProbeFunction* probe_function,
              const std::string& probe_statement_str,
              std::string* result) const override;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_SYSTEM_HELPER_INVOKER_DEBUGD_IMPL_H_
