// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hammerd/fmap_utils.h"
#include "hammerd/fuzzed_ec_image.h"
#include "hammerd/update_fw.h"
#include "hammerd/vb21_struct.h"

namespace hammerd {

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

namespace {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FirmwareUpdater fw_updater_(nullptr);  // no endpoint required to load EC
  FuzzedDataProvider data_provider(data, size);
  FuzzedEcImage ec_image_factory(&data_provider);

  fw_updater_.LoadEcImage(ec_image_factory.Create());

  return 0;
}
}  // namespace
}  // namespace hammerd
