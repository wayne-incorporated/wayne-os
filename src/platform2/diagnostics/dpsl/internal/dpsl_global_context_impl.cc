// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/dpsl/internal/dpsl_global_context_impl.h"

#include <atomic>
#include <memory>

#include <base/check.h>
#include <base/lazy_instance.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

namespace diagnostics {

namespace {

// Whether an instance of DpslGlobalContextImpl was created.
base::LazyInstance<std::atomic_flag>::Leaky g_global_context_created =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

// static
void DpslGlobalContextImpl::CleanGlobalCounterForTesting() {
  g_global_context_created.Get().clear();
}

DpslGlobalContextImpl::DpslGlobalContextImpl() {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
}

DpslGlobalContextImpl::~DpslGlobalContextImpl() {
  CHECK(thread_checker_.CalledOnValidThread());
}

// static
std::unique_ptr<DpslGlobalContext> DpslGlobalContext::Create() {
  CHECK(!g_global_context_created.Get().test_and_set())
      << "Duplicate DpslGlobalContext instances";

  return std::make_unique<DpslGlobalContextImpl>();
}

}  // namespace diagnostics
