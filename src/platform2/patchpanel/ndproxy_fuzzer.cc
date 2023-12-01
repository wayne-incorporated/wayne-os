// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/ndproxy.h"

#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace patchpanel {

namespace {

constexpr MacAddress guest_if_mac({0xd2, 0x47, 0xf7, 0xc5, 0x9e, 0x53});

class NDProxyForFuzzer : public NDProxy {
 public:
  void Fuzz(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);
    size_t nd_hdr_len = provider.ConsumeIntegralInRange<size_t>(0, size);
    uint8_t opt_type = provider.ConsumeIntegral<uint8_t>();
    uint8_t* buffer = new uint8_t[size];

    TranslateNDPacket(data, size, guest_if_mac, std::nullopt, std::nullopt,
                      buffer);

    memcpy(buffer, data, size);
    const nd_opt_prefix_info* prefix_info = GetPrefixInfoOption(buffer, size);
    // Just to consume GetPrefixInfoOption() output
    if (prefix_info != nullptr)
      buffer[0] = prefix_info->nd_opt_pi_prefix_len;

    ReplaceMacInIcmpOption(buffer, size, nd_hdr_len, opt_type, guest_if_mac);

    delete[] buffer;
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);
  NDProxyForFuzzer ndproxy;
  ndproxy.Fuzz(data, size);

  return 0;
}

}  // namespace
}  // namespace patchpanel
