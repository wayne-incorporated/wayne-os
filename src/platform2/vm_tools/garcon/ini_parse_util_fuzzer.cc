// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <stddef.h>
#include <stdint.h>

#include <fuzzer/FuzzedDataProvider.h>

#include "vm_tools/garcon/ini_parse_util.h"

namespace {
constexpr size_t kRandomStringLength = 1024;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Just call the different functions in the ini parser after generating
  // random strings.
  FuzzedDataProvider data_provider(data, size);
  std::string str =
      data_provider.ConsumeRandomLengthString(kRandomStringLength);
  vm_tools::garcon::ParseGroupName(str);
  std::string locale =
      data_provider.ConsumeRandomLengthString(kRandomStringLength);
  vm_tools::garcon::ExtractKeyLocale(locale);
  std::string keyval =
      data_provider.ConsumeRandomLengthString(kRandomStringLength);
  vm_tools::garcon::ExtractKeyValuePair(keyval);
  std::string unescapestr =
      data_provider.ConsumeRandomLengthString(kRandomStringLength);
  vm_tools::garcon::UnescapeString(unescapestr);
  std::string multistr =
      data_provider.ConsumeRandomLengthString(kRandomStringLength);
  std::vector<std::string> out;
  std::string delim = data_provider.ConsumeBytesAsString(1);
  if (delim.empty()) {
    vm_tools::garcon::ParseMultiString(multistr, &out);
  } else {
    vm_tools::garcon::ParseMultiString(multistr, &out, delim[0]);
  }

  return 0;
}
