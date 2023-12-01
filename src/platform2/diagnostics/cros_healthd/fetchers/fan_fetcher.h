// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_FAN_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_FAN_FETCHER_H_

#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback_forward.h>
#include <base/memory/weak_ptr.h>

#include "diagnostics/cros_healthd/fetchers/base_fetcher.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// Relative filepath used to determine whether a device has a Google EC.
constexpr char kRelativeCrosEcPath[] = "sys/class/chromeos/cros_ec";

// The FanFetcher class is responsible for gathering fan info reported by
// cros_healthd.
class FanFetcher final : public BaseFetcher {
 public:
  using FetchFanInfoCallback =
      base::OnceCallback<void(ash::cros_healthd::mojom::FanResultPtr)>;

  using BaseFetcher::BaseFetcher;

  // Returns either a list of data about each of the device's fans or the error
  // that occurred retrieving the information.
  void FetchFanInfo(FetchFanInfoCallback callback);

 private:
  // Handles the executor's response to a GetFanSpeed IPC.
  void HandleFanSpeedResponse(
      FetchFanInfoCallback callback,
      ash::cros_healthd::mojom::ExecutedProcessResultPtr result);

  // Must be the last member of the class, so that it's destroyed first when an
  // instance of the class is destroyed. This will prevent any outstanding
  // callbacks from being run and segfaulting.
  base::WeakPtrFactory<FanFetcher> weak_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_FAN_FETCHER_H_
