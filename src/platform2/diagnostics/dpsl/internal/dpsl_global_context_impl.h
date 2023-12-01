// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_DPSL_INTERNAL_DPSL_GLOBAL_CONTEXT_IMPL_H_
#define DIAGNOSTICS_DPSL_INTERNAL_DPSL_GLOBAL_CONTEXT_IMPL_H_

#include <base/threading/thread_checker_impl.h>

#include "diagnostics/dpsl/public/dpsl_global_context.h"

namespace diagnostics {

// Real implementation of the DpslGlobalContext interface.
//
// Currently only does the logging configuration on construction.
class DpslGlobalContextImpl final : public DpslGlobalContext {
 public:
  // Cleans global counter which prevents from calling
  // |DpslGlobalContext::Create()| more than once per process.
  static void CleanGlobalCounterForTesting();

  DpslGlobalContextImpl();
  DpslGlobalContextImpl(const DpslGlobalContextImpl&) = delete;
  DpslGlobalContextImpl& operator=(const DpslGlobalContextImpl&) = delete;

  ~DpslGlobalContextImpl() override;

 private:
  base::ThreadCheckerImpl thread_checker_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_DPSL_INTERNAL_DPSL_GLOBAL_CONTEXT_IMPL_H_
