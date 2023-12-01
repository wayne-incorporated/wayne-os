// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/system/helper_invoker_direct_impl.h"

#include <string>

#include "runtime_probe/probe_function.h"

namespace runtime_probe {

bool HelperInvokerDirectImpl::Invoke(const ProbeFunction* probe_function,
                                     const std::string& probe_statement_str,
                                     std::string* result) const {
  int res = probe_function->EvalInHelper(result);
  return res == 0;
}

}  // namespace runtime_probe
