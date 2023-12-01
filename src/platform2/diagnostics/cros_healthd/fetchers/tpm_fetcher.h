// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_TPM_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_TPM_FETCHER_H_

#include <string>
#include <vector>

#include <attestation/proto_bindings/interface.pb.h>
#include <base/functional/callback_forward.h>
#include <base/memory/weak_ptr.h>
#include <brillo/errors/error.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>

#include "diagnostics/cros_healthd/fetchers/base_fetcher.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

inline constexpr auto kFileTpmDidVid = "sys/class/tpm/tpm0/did_vid";

class TpmFetcher final : public BaseFetcher {
 public:
  using BaseFetcher::BaseFetcher;

  using FetchTpmInfoCallback =
      base::OnceCallback<void(ash::cros_healthd::mojom::TpmResultPtr)>;
  // Returns a structure with either the device's tpm data or the error
  // that occurred fetching the information.
  void FetchTpmInfo(FetchTpmInfoCallback&& callback);

 private:
  void FetchVersion();
  void HandleVersion(brillo::Error* err,
                     const tpm_manager::GetVersionInfoReply& reply);
  void FetchStatus();
  void HandleStatus(brillo::Error* err,
                    const tpm_manager::GetTpmNonsensitiveStatusReply& reply);
  void FetchDictionaryAttack();
  void HandleDictionaryAttack(
      brillo::Error* err,
      const tpm_manager::GetDictionaryAttackInfoReply& reply);
  void FetchAttestation();
  void HandleAttestation(brillo::Error* err,
                         const attestation::GetStatusReply& reply);
  void FetchSupportedFeatures();
  void HandleSupportedFeatures(
      brillo::Error* err, const tpm_manager::GetSupportedFeaturesReply& reply);
  void CheckAndSendInfo();
  void SendError(const std::string& message);
  void SendResult(ash::cros_healthd::mojom::TpmResultPtr result);

 private:
  // Pending callbacks to be fulfilled.
  std::vector<FetchTpmInfoCallback> pending_callbacks_;
  // The fetched info.
  ash::cros_healthd::mojom::TpmInfoPtr info_;
  // Must be the last member of the class, so that it's destroyed first when an
  // instance of the class is destroyed. This will prevent any outstanding
  // callbacks from being run and segfaulting.
  base::WeakPtrFactory<TpmFetcher> weak_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_TPM_FETCHER_H_
