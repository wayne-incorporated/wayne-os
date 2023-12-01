// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Fuzzer for PasswordAuthorizationDelegate.

#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "trunks/password_authorization_delegate.h"

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider data_provider(data, size);
  trunks::PasswordAuthorizationDelegate delegate(
      data_provider.ConsumeRandomLengthString(
          sizeof(trunks::TPM2B_DIGEST().buffer)));
  std::string auth;
  constexpr int kMaxRandomAuthLength = 1024;
  // All the input params here are ignored, only the password in the constructor
  // actually matters.
  delegate.GetCommandAuthorization("", false, false, &auth);

  // The first parameter is ignored.
  delegate.CheckResponseAuthorization(
      "", data_provider.ConsumeRandomLengthString(kMaxRandomAuthLength));
  return 0;
}
