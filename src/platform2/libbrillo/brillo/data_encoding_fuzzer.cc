// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include <brillo/data_encoding.h>

#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace {
constexpr int kMaxStringLength = 256;
constexpr int kMaxParamsSize = 8;

void FuzzUrlEncodeDecode(FuzzedDataProvider* provider) {
  brillo::data_encoding::UrlEncode(
      provider->ConsumeRandomLengthString(kMaxStringLength).c_str(),
      provider->ConsumeBool());

  brillo::data_encoding::UrlDecode(
      provider->ConsumeRandomLengthString(kMaxStringLength).c_str());
}

void FuzzWebParamsEncodeDecode(FuzzedDataProvider* provider) {
  brillo::data_encoding::WebParamList param_list;
  const auto num_params = provider->ConsumeIntegralInRange(0, kMaxParamsSize);
  for (auto i = 0; i < num_params; i++) {
    param_list.push_back(std::pair<std::string, std::string>(
        provider->ConsumeRandomLengthString(kMaxStringLength),
        provider->ConsumeRandomLengthString(kMaxStringLength)));
  }
  brillo::data_encoding::WebParamsEncode(param_list, provider->ConsumeBool());

  brillo::data_encoding::WebParamsDecode(
      provider->ConsumeRandomLengthString(kMaxStringLength));
}

void FuzzBase64EncodeDecode(FuzzedDataProvider* provider) {
  brillo::data_encoding::Base64Encode(
      provider->ConsumeRandomLengthString(kMaxStringLength));
  brillo::Blob output;
  brillo::data_encoding::Base64Decode(
      provider->ConsumeRandomLengthString(kMaxStringLength), &output);
}

bool IgnoreLogging(int, const char*, int, size_t, const std::string&) {
  return true;
}

}  // namespace

class Environment {
 public:
  Environment() {
    // Disable logging. Normally this would be done with logging::SetMinLogLevel
    // but that doesn't work for brillo::Error because it's not using the
    // LOG(ERROR) macro which is where the actual log level check occurs.
    logging::SetLogMessageHandler(&IgnoreLogging);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);
  FuzzUrlEncodeDecode(&data_provider);
  FuzzWebParamsEncodeDecode(&data_provider);
  FuzzBase64EncodeDecode(&data_provider);
  return 0;
}
