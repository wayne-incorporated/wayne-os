// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BASE_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BASE_FETCHER_H_

#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {

class BaseFetcher {
 public:
  explicit BaseFetcher(Context* context) : context_(context) {
    DCHECK(context_);
  }
  BaseFetcher(const BaseFetcher&) = delete;
  BaseFetcher& operator=(const BaseFetcher&) = delete;
  ~BaseFetcher() = default;

 protected:
  // Unowned pointer that should outlive this instance.
  Context* const context_ = nullptr;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BASE_FETCHER_H_
