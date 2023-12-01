// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BACKLIGHT_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BACKLIGHT_FETCHER_H_

#include "diagnostics/cros_healthd/fetchers/base_fetcher.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

class BacklightFetcher final : public BaseFetcher {
 public:
  using BaseFetcher::BaseFetcher;

  // Returns a structure with either the device's backlight info or the error
  // that occurred fetching the information.
  ash::cros_healthd::mojom::BacklightResultPtr FetchBacklightInfo();
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BACKLIGHT_FETCHER_H_
