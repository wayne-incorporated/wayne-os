// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMASTER_CONVERSION_H_
#define ARC_KEYMASTER_CONVERSION_H_

#include <memory>
#include <vector>

#include <keymaster/android_keymaster.h>
#include <mojo/keymaster.mojom.h>

namespace arc {
namespace keymaster {

// Keymaster request methods.
std::unique_ptr<::keymaster::GetKeyCharacteristicsRequest>
MakeGetKeyCharacteristicsRequest(
    const ::arc::mojom::GetKeyCharacteristicsRequestPtr& request);

std::unique_ptr<::keymaster::GenerateKeyRequest> MakeGenerateKeyRequest(
    const std::vector<arc::mojom::KeyParameterPtr>& data);

std::unique_ptr<::keymaster::ImportKeyRequest> MakeImportKeyRequest(
    const arc::mojom::ImportKeyRequestPtr& request);

std::unique_ptr<::keymaster::ExportKeyRequest> MakeExportKeyRequest(
    const arc::mojom::ExportKeyRequestPtr& request);

std::unique_ptr<::keymaster::AttestKeyRequest> MakeAttestKeyRequest(
    const arc::mojom::AttestKeyRequestPtr& request);

std::unique_ptr<::keymaster::UpgradeKeyRequest> MakeUpgradeKeyRequest(
    const arc::mojom::UpgradeKeyRequestPtr& request);

std::unique_ptr<::keymaster::BeginOperationRequest> MakeBeginOperationRequest(
    const arc::mojom::BeginRequestPtr& request);

std::unique_ptr<::keymaster::UpdateOperationRequest> MakeUpdateOperationRequest(
    const arc::mojom::UpdateRequestPtr& request);

std::unique_ptr<::keymaster::FinishOperationRequest> MakeFinishOperationRequest(
    const arc::mojom::FinishRequestPtr& request);

// Mojo result methods.
arc::mojom::GetKeyCharacteristicsResultPtr MakeGetKeyCharacteristicsResult(
    const ::keymaster::GetKeyCharacteristicsResponse& km_response);

arc::mojom::GenerateKeyResultPtr MakeGenerateKeyResult(
    const ::keymaster::GenerateKeyResponse& km_response);

arc::mojom::ImportKeyResultPtr MakeImportKeyResult(
    const ::keymaster::ImportKeyResponse& km_response);

arc::mojom::ExportKeyResultPtr MakeExportKeyResult(
    const ::keymaster::ExportKeyResponse& km_response);

arc::mojom::AttestKeyResultPtr MakeAttestKeyResult(
    const ::keymaster::AttestKeyResponse& km_response);

arc::mojom::UpgradeKeyResultPtr MakeUpgradeKeyResult(
    const ::keymaster::UpgradeKeyResponse& km_response);

arc::mojom::BeginResultPtr MakeBeginResult(
    const ::keymaster::BeginOperationResponse& km_response);

arc::mojom::UpdateResultPtr MakeUpdateResult(
    const ::keymaster::UpdateOperationResponse& km_response);

arc::mojom::FinishResultPtr MakeFinishResult(
    const ::keymaster::FinishOperationResponse& km_response);

// Convenience helper methods.
std::vector<uint8_t> ConvertToMojo(const uint8_t* data, const size_t size);

std::vector<std::vector<uint8_t>> ConvertToMojo(
    const keymaster_cert_chain_t& cert);

std::vector<::arc::mojom::KeyParameterPtr> ConvertToMojo(
    const keymaster_key_param_set_t& set);

void ConvertToMessage(const std::vector<uint8_t>& data,
                      ::keymaster::Buffer* out);

void ConvertToMessage(const std::vector<uint8_t>& clientId,
                      const std::vector<uint8_t>& appData,
                      ::keymaster::AuthorizationSet* params);

void ConvertToMessage(const std::vector<arc::mojom::KeyParameterPtr>& data,
                      ::keymaster::AuthorizationSet* out);

}  // namespace keymaster
}  // namespace arc

#endif  // ARC_KEYMASTER_CONVERSION_H_
