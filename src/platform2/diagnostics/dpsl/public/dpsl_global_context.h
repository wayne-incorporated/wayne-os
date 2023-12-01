// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_DPSL_PUBLIC_DPSL_GLOBAL_CONTEXT_H_
#define DIAGNOSTICS_DPSL_PUBLIC_DPSL_GLOBAL_CONTEXT_H_

#include <memory>

namespace diagnostics {

// Interface of the class that performs the process-wide DPSL initialization and
// holds any global resources it needs. This object must be kept alive as long
// as any other DPSL functionality is used.
//
// EXAMPLE USAGE:
//
//   int main() {
//     auto global_context = DpslGlobalContext::Create();
//     ...
//
// NOTE ON THREADING MODEL: This class is NOT thread-safe. It must be destroyed
// on the same thread on which it was created.
//
// NOTE ON LIFETIME: At most one instance of this class must be created during
// the whole lifetime of the current process.
class DpslGlobalContext {
 public:
  // Factory method that returns an instance of the real implementation of this
  // interface.
  //
  // The return value is guaranteed to be non-null.
  static std::unique_ptr<DpslGlobalContext> Create();

  virtual ~DpslGlobalContext() = default;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_DPSL_PUBLIC_DPSL_GLOBAL_CONTEXT_H_
