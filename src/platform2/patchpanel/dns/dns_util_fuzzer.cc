// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "patchpanel/dns/dns_util.h"

namespace patchpanel {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  FuzzedDataProvider provider(data, size);
  std::string out;
  DNSDomainFromDot(provider.ConsumeRandomLengthString(2000), &out);
  DnsDomainToString(provider.ConsumeRandomLengthString(2000));

  return 0;
}

}  // namespace patchpanel
