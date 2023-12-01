// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <string>

#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "shill/service.h"
#include "shill/store/fake_store.h"

namespace shill {

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  // const std::string fuzzed_str(reinterpret_cast<const char*>(data), size);
  FakeStore storage;
  FuzzedDataProvider provider(data, size);

  std::string id = Service::SanitizeStorageIdentifier(
      provider.ConsumeRandomLengthString(1024));
  std::string key1 = provider.ConsumeRandomLengthString(1024);
  std::string key2 = provider.ConsumeRandomLengthString(1024);
  std::string value = provider.ConsumeRandomLengthString(1024);
  std::string expected_value;
  std::string default_value = provider.ConsumeRemainingBytesAsString();
  Service::SaveStringOrClear(&storage, id, key1, value);
  Service::LoadString(&storage, id, key1, default_value, &expected_value);
  Service::LoadString(&storage, id, key2, default_value, &expected_value);
  return 0;
}

}  // namespace shill
