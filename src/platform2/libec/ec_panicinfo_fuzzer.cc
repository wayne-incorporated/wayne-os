// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/containers/span.h>

#include "libec/ec_panicinfo.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, unsigned int size) {
  auto result = ec::ParsePanicInfo(base::make_span(data, size));
  return 0;
}
