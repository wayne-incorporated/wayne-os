// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_TSS_UTILS_EXTENDED_APIS_H_
#define LIBHWSEC_TSS_UTILS_EXTENDED_APIS_H_

#include <malloc.h>

#include <brillo/secure_string.h>
#include <trousers/trousers.h>
#include <trousers/tss.h>

extern "C" inline TSS_RESULT Tspi_Context_SecureFreeMemory(
    TSS_HCONTEXT hContext, BYTE* rgbMemory) {
  brillo::SecureClearBytes(rgbMemory, malloc_usable_size(rgbMemory));
  return Tspi_Context_FreeMemory(hContext, rgbMemory);
}

#endif  // LIBHWSEC_TSS_UTILS_EXTENDED_APIS_H_
