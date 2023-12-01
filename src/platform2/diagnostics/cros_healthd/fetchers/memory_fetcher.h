// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_MEMORY_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_MEMORY_FETCHER_H_

#include <optional>
#include <string>
#include <vector>

#include "diagnostics/cros_healthd/executor/constants.h"
#include "diagnostics/cros_healthd/fetchers/base_fetcher.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// The MemoryFetcher class is responsible for gathering memory info.
class MemoryFetcher final : public BaseFetcher {
 public:
  using FetchMemoryInfoCallback =
      base::OnceCallback<void(ash::cros_healthd::mojom::MemoryResultPtr)>;
  using BaseFetcher::BaseFetcher;
  // Returns a structure with either the device's memory info or the error that
  // occurred fetching the information.
  void FetchMemoryInfo(FetchMemoryInfoCallback callback);

 private:
  using OptionalProbeErrorPtr =
      std::optional<ash::cros_healthd::mojom::ProbeErrorPtr>;
  void FetchMemoryEncryptionInfo();
  void FetchMktmeInfo();
  void FetchTmeInfo();
  void HandleReadTmeCapabilityMsr(
      ash::cros_healthd::mojom::NullableUint64Ptr val);
  void HandleReadTmeActivateMsr(
      ash::cros_healthd::mojom::NullableUint64Ptr val);
  void ExtractTmeInfoFromMsr();
  void CreateResultAndSendBack();
  void CreateErrorAndSendBack(ash::cros_healthd::mojom::ErrorType error_type,
                              const std::string& message);
  void SendBackResult(ash::cros_healthd::mojom::MemoryResultPtr result);
  void ParseProcMemInfo(ash::cros_healthd::mojom::MemoryInfo* info);
  void ParseProcVmStat(ash::cros_healthd::mojom::MemoryInfo* info);
  uint64_t tme_capability_value_;
  uint64_t tme_activate_value_;
  ash::cros_healthd::mojom::MemoryInfo mem_info_;
  std::vector<FetchMemoryInfoCallback> pending_callbacks_;
  base::WeakPtrFactory<MemoryFetcher> weak_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_MEMORY_FETCHER_H_
