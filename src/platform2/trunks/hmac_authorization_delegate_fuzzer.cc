// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Fuzzer for HmacAuthorizationDelegate.

#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "trunks/hmac_authorization_delegate.h"
#include "trunks/tpm_generated.h"

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider data_provider(data, size);
  trunks::HmacAuthorizationDelegate delegate;
  // This isn't used for anything aside from CHECK() for a nonzero value, so
  // don't fuzz it.
  constexpr int kSessionHandle = 1;
  // The nonce's need to be between 16 and 32 bytes (exclusive) or the init
  // will immediately fail, but we should still fuzz a range of lengths.
  constexpr int kNonceSizeMin = 0;
  constexpr int kNonceSizeMax = 64;
  trunks::TPM2B_NONCE tpm_nonce;
  trunks::TPM2B_NONCE caller_nonce;
  tpm_nonce.size =
      data_provider.ConsumeIntegralInRange(kNonceSizeMin, kNonceSizeMax);
  caller_nonce.size =
      data_provider.ConsumeIntegralInRange(kNonceSizeMin, kNonceSizeMax);
  if (tpm_nonce.size) {
    std::vector<uint8_t> rand_data =
        data_provider.ConsumeBytes<uint8_t>(tpm_nonce.size);
    // Backfill with zeroes in case the data provider ran out of stream.
    rand_data.resize(tpm_nonce.size);
    memcpy(tpm_nonce.buffer, rand_data.data(), rand_data.size());
  }
  if (caller_nonce.size) {
    std::vector<uint8_t> rand_data =
        data_provider.ConsumeBytes<uint8_t>(caller_nonce.size);
    // Backfill with zeroes in case the data provider ran out of stream.
    rand_data.resize(caller_nonce.size);
    memcpy(caller_nonce.buffer, rand_data.data(), rand_data.size());
  }
  constexpr int kMaxRandomStringLength = 128;
  delegate.InitSession(
      kSessionHandle, tpm_nonce, caller_nonce,
      data_provider.ConsumeRandomLengthString(kMaxRandomStringLength),
      data_provider.ConsumeRandomLengthString(kMaxRandomStringLength),
      data_provider.ConsumeBool());

  // Randomly decide to get the command auth or check the response auth.
  if (data_provider.ConsumeBool()) {
    std::string auth;
    delegate.GetCommandAuthorization(
        data_provider.ConsumeRandomLengthString(kMaxRandomStringLength),
        data_provider.ConsumeBool(), data_provider.ConsumeBool(), &auth);
  } else {
    delegate.CheckResponseAuthorization(
        data_provider.ConsumeRandomLengthString(kMaxRandomStringLength),
        data_provider.ConsumeRandomLengthString(kMaxRandomStringLength));
  }
  return 0;
}
