/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <fuzzer/FuzzedDataProvider.h>

#include <brillo/data_encoding.h>
#include <brillo/url_utils.h>

namespace {
// Set arbitrary limitation on long inputs to make the fuzzer faster
constexpr int kMaxStringLength = 256;
constexpr int kMaxParamsSize = 8;

void FuzzCombine(FuzzedDataProvider* provider) {
  std::ignore = brillo::url::Combine(
      provider->ConsumeRandomLengthString(kMaxStringLength),
      provider->ConsumeRandomLengthString(kMaxStringLength));
}

void FuzzGetQueryString(FuzzedDataProvider* provider) {
  brillo::url::GetQueryString(
      provider->ConsumeRandomLengthString(kMaxStringLength),
      provider->ConsumeBool());
}

void FuzzGetQueryStringParameters(FuzzedDataProvider* provider) {
  brillo::url::GetQueryStringParameters(
      provider->ConsumeRandomLengthString(kMaxStringLength));
}

void FuzzGetQueryStringValue(FuzzedDataProvider* provider) {
  brillo::url::GetQueryStringValue(
      provider->ConsumeRandomLengthString(kMaxStringLength),
      provider->ConsumeRandomLengthString(kMaxStringLength));
}

void FuzzTrimOffQueryString(FuzzedDataProvider* provider) {
  auto url = provider->ConsumeRandomLengthString(kMaxStringLength);
  brillo::url::TrimOffQueryString(&url);
}

void FuzzRemoveQueryString(FuzzedDataProvider* provider) {
  std::ignore = brillo::url::RemoveQueryString(
      provider->ConsumeRandomLengthString(kMaxStringLength),
      provider->ConsumeBool());
}

void FuzzAppendQueryParam(FuzzedDataProvider* provider) {
  std::ignore = brillo::url::AppendQueryParam(
      provider->ConsumeRandomLengthString(kMaxStringLength),
      provider->ConsumeRandomLengthString(kMaxStringLength),
      provider->ConsumeRandomLengthString(kMaxStringLength));
}

void FuzzAppendQueryParams(FuzzedDataProvider* provider) {
  brillo::data_encoding::WebParamList param_list;
  const auto num_params = provider->ConsumeIntegralInRange(0, kMaxParamsSize);
  for (auto i = 0; i < num_params; i++) {
    param_list.emplace_back(
        provider->ConsumeRandomLengthString(kMaxStringLength),
        provider->ConsumeRandomLengthString(kMaxStringLength));
  }
  std::ignore = brillo::url::AppendQueryParams(
      provider->ConsumeRandomLengthString(kMaxStringLength), param_list);
}

void FuzzHasQueryString(FuzzedDataProvider* provider) {
  brillo::url::HasQueryString(
      provider->ConsumeRandomLengthString(kMaxStringLength));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider data_provider(data, size);
  FuzzCombine(&data_provider);
  FuzzGetQueryString(&data_provider);
  FuzzGetQueryStringParameters(&data_provider);
  FuzzGetQueryStringValue(&data_provider);
  FuzzTrimOffQueryString(&data_provider);
  FuzzRemoveQueryString(&data_provider);
  FuzzAppendQueryParam(&data_provider);
  FuzzAppendQueryParams(&data_provider);
  FuzzHasQueryString(&data_provider);
  return 0;
}
