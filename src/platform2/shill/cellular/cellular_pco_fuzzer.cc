// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <fuzzer/FuzzedDataProvider.h>

#include "shill/cellular/cellular_pco.h"

#include <base/logging.h>

namespace shill {
namespace {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  FuzzedDataProvider data_provider(data, size);

  // Prepare a few random elements to search for.
  std::vector<uint16_t> elements(
      data_provider.ConsumeIntegralInRange<uint32_t>(0, 10));
  for (size_t i = 0; i < elements.size(); i++)
    elements[i] = data_provider.ConsumeIntegral<uint16_t>();

  const std::string& str = data_provider.ConsumeRemainingBytesAsString();
  const std::vector<uint8_t> raw_data(str.begin(), str.end());
  std::unique_ptr<CellularPco> pco = CellularPco::CreateFromRawData(raw_data);

  if (pco)
    for (auto e : elements)
      pco->FindElement(e);

  return 0;
}

}  // namespace
}  // namespace shill
