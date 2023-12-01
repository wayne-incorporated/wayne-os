// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMINT_CONVERSION_H_
#define ARC_KEYMINT_CONVERSION_H_

#include <memory>
#include <vector>

#include <keymaster/android_keymaster.h>
#include <mojo/keymint.mojom.h>

namespace arc::keymint {

// Convenience helper methods.
std::vector<uint8_t> ConvertFromKeymasterMessage(const uint8_t* data,
                                                 const size_t size);

std::vector<std::vector<uint8_t>> ConvertFromKeymasterMessage(
    const keymaster_cert_chain_t& cert);

std::vector<::arc::mojom::keymint::KeyParameterPtr> ConvertFromKeymasterMessage(
    const keymaster_key_param_set_t& set);

void ConvertToKeymasterMessage(const std::vector<uint8_t>& data,
                               ::keymaster::Buffer* out);

void ConvertToKeymasterMessage(const std::vector<uint8_t>& clientId,
                               const std::vector<uint8_t>& appData,
                               ::keymaster::AuthorizationSet* params);

void ConvertToKeymasterMessage(
    const std::vector<arc::mojom::keymint::KeyParameterPtr>& data,
    ::keymaster::AuthorizationSet* out);

// Request Methods.
std::unique_ptr<::keymaster::GetKeyCharacteristicsRequest>
MakeGetKeyCharacteristicsRequest(
    const ::arc::mojom::keymint::GetKeyCharacteristicsRequestPtr& request,
    const int32_t keymint_message_version);

std::unique_ptr<::keymaster::GenerateKeyRequest> MakeGenerateKeyRequest(
    const std::vector<arc::mojom::keymint::KeyParameterPtr>& data,
    const int32_t keymint_message_version);

// Mojo Result Methods.
std::optional<std::vector<arc::mojom::keymint::KeyCharacteristicsPtr>>
MakeGetKeyCharacteristicsResult(
    const ::keymaster::GetKeyCharacteristicsResponse& km_response,
    uint32_t& error);

std::optional<arc::mojom::keymint::KeyCreationResultPtr> MakeGenerateKeyResult(
    const ::keymaster::GenerateKeyResponse& km_response, uint32_t& error);

}  // namespace arc::keymint

#endif  // ARC_KEYMINT_CONVERSION_H_
