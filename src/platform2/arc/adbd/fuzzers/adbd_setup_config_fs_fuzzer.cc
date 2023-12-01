/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "arc/adbd/adbd.h"

#include <cstddef>
#include <cstdint>

#include <fuzzer/FuzzedDataProvider.h>

#include <base/logging.h>

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  int MAX_LEN = 255;

  if (size < 1)
    return 0;

  FuzzedDataProvider data_provider(data, size);

  int32_t serial_number_length =
      data_provider.ConsumeIntegralInRange<int32_t>(1, MAX_LEN);
  int32_t usb_product_id_length =
      data_provider.ConsumeIntegralInRange<int32_t>(1, MAX_LEN);
  int32_t usb_product_name_length =
      data_provider.ConsumeIntegralInRange<int32_t>(1, MAX_LEN);

  std::string serial_number =
      data_provider.ConsumeBytesAsString(serial_number_length);
  std::string usb_product_id =
      data_provider.ConsumeBytesAsString(usb_product_id_length);
  std::string usb_product_name =
      data_provider.ConsumeBytesAsString(usb_product_name_length);

  adbd::SetupConfigFS(serial_number, usb_product_id, usb_product_name);

  return 0;
}
