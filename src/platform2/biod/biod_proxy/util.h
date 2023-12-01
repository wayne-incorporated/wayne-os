// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_PROXY_UTIL_H_
#define BIOD_BIOD_PROXY_UTIL_H_

#include <brillo/brillo_export.h>

#include "biod/proto_bindings/messages.pb.h"

namespace biod {

BRILLO_EXPORT const char* ScanResultToString(ScanResult result);
BRILLO_EXPORT const char* FingerprintErrorToString(
    const FingerprintError& error);

}  // namespace biod

#endif  // BIOD_BIOD_PROXY_UTIL_H_
