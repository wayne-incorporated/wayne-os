// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <string>

#include <libmbim-glib/libmbim-glib.h>

#include <base/check.h>

#include "hermes/libmbim_impl.h"
#include "hermes/modem_mbim.h"

namespace hermes {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!size)
    return 0;

  g_autoptr(MbimMessage) response =
      mbim_message_new(reinterpret_cast<const guint8*>(data), size);
  std::string eid;
  if (ModemMbim::ParseEidApduResponseForTesting(
          response, &eid, std::make_unique<LibmbimImpl>()))
    CHECK(eid.length());

  return 0;
}

}  // namespace hermes
