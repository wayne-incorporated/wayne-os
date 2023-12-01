// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_SYSTEM_HELPER_INVOKER_DIRECT_IMPL_H_
#define RUNTIME_PROBE_SYSTEM_HELPER_INVOKER_DIRECT_IMPL_H_

#include "runtime_probe/system/helper_invoker.h"

#include <string>

namespace runtime_probe {

class HelperInvokerDirectImpl : public HelperInvoker {
  using HelperInvoker::HelperInvoker;

 public:
  // Invoke the helper directly in the same process.
  //
  // The implementation is used by factory_runtime_probe and unit tests. In
  // factory, we don't want to sandbox the helper.
  bool Invoke(const ProbeFunction* probe_function,
              const std::string& probe_statement_str,
              std::string* result) const override;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_SYSTEM_HELPER_INVOKER_DIRECT_IMPL_H_
