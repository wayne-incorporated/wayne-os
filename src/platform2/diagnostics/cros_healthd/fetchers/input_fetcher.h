// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_INPUT_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_INPUT_FETCHER_H_

#include <base/functional/callback_forward.h>

#include "diagnostics/cros_healthd/fetchers/base_fetcher.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// Fetches the input related information.
class InputFetcher final : public BaseFetcher {
 public:
  using BaseFetcher::BaseFetcher;

  using ResultCallback =
      base::OnceCallback<void(ash::cros_healthd::mojom::InputResultPtr)>;
  void Fetch(ResultCallback callback);
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_INPUT_FETCHER_H_
