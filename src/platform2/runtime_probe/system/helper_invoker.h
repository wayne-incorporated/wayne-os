// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_SYSTEM_HELPER_INVOKER_H_
#define RUNTIME_PROBE_SYSTEM_HELPER_INVOKER_H_

#include <string>

namespace runtime_probe {

class ProbeFunction;

class HelperInvoker {
 public:
  HelperInvoker() = default;
  HelperInvoker(const HelperInvoker&) = delete;
  HelperInvoker& operator=(const HelperInvoker&) = delete;
  virtual ~HelperInvoker() = default;

  // Invokes an individual helper instance to perform the actual probing actions
  // in a properly secured environment.  The |probe_statement| is the input
  // of the helper process.  The method is a blocking call that returns after
  // the helper process ends.  If it successes, the method stores the probed
  // result in |result| and returns |true|; otherwise, the method returns
  // |false|.
  virtual bool Invoke(const ProbeFunction* probe_function,
                      const std::string& probe_statement_str,
                      std::string* result) const = 0;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_SYSTEM_HELPER_INVOKER_H_
