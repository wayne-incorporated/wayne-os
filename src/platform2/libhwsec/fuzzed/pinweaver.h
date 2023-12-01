// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_PINWEAVER_H_
#define LIBHWSEC_FUZZED_PINWEAVER_H_

#include <algorithm>
#include <optional>
#include <type_traits>
#include <vector>

#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/backend/pinweaver.h"
#include "libhwsec/fuzzed/basic_objects.h"

namespace hwsec {

template <>
struct FuzzedObject<PinWeaver::CredentialTreeResult> {
  PinWeaver::CredentialTreeResult operator()(
      FuzzedDataProvider& provider) const {
    return PinWeaver::CredentialTreeResult{
        .error = FuzzedObject<PinWeaver::CredentialTreeResult::ErrorCode>()(
            provider),
        .new_root = FuzzedObject<brillo::Blob>()(provider),
        .new_cred_metadata =
            FuzzedObject<std::optional<brillo::Blob>>()(provider),
        .new_mac = FuzzedObject<std::optional<brillo::Blob>>()(provider),
        .he_secret =
            FuzzedObject<std::optional<brillo::SecureBlob>>()(provider),
        .reset_secret =
            FuzzedObject<std::optional<brillo::SecureBlob>>()(provider),
        .server_nonce = FuzzedObject<std::optional<brillo::Blob>>()(provider),
        .iv = FuzzedObject<std::optional<brillo::Blob>>()(provider),
        .encrypted_he_secret =
            FuzzedObject<std::optional<brillo::Blob>>()(provider),
    };
  }
};

template <>
struct FuzzedObject<PinWeaver::GetLogResult::LogEntry> {
  PinWeaver::GetLogResult::LogEntry operator()(
      FuzzedDataProvider& provider) const {
    return PinWeaver::GetLogResult::LogEntry{
        .type = FuzzedObject<PinWeaver::GetLogResult::LogEntryType>()(provider),
        .label = FuzzedObject<uint64_t>()(provider),
        .root = FuzzedObject<brillo::Blob>()(provider),
        .mac = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<PinWeaver::GetLogResult> {
  PinWeaver::GetLogResult operator()(FuzzedDataProvider& provider) const {
    return PinWeaver::GetLogResult{
        .root_hash = FuzzedObject<brillo::Blob>()(provider),
        .log_entries =
            FuzzedObject<std::vector<PinWeaver::GetLogResult::LogEntry>>()(
                provider),
    };
  }
};

template <>
struct FuzzedObject<PinWeaver::ReplayLogOperationResult> {
  PinWeaver::ReplayLogOperationResult operator()(
      FuzzedDataProvider& provider) const {
    return PinWeaver::ReplayLogOperationResult{
        .new_cred_metadata = FuzzedObject<brillo::Blob>()(provider),
        .new_mac = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<PinWeaver::PinWeaverEccPoint> {
  PinWeaver::PinWeaverEccPoint operator()(FuzzedDataProvider& provider) const {
    PinWeaver::PinWeaverEccPoint result;
    auto bytes = provider.ConsumeBytes<uint8_t>(PinWeaverEccPointSize);
    std::copy_n(std::begin(bytes), bytes.size(), std::begin(result.x));

    bytes = provider.ConsumeBytes<uint8_t>(PinWeaverEccPointSize);
    std::copy_n(std::begin(bytes), bytes.size(), std::begin(result.y));

    return result;
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_PINWEAVER_H_
