// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_ENCRYPTION_H_
#define LIBHWSEC_FUZZED_ENCRYPTION_H_

#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/backend/encryption.h"
#include "libhwsec/fuzzed/basic_objects.h"

namespace hwsec {

template <>
struct FuzzedObject<Encryption::EncryptionOptions> {
  Encryption::EncryptionOptions operator()(FuzzedDataProvider& provider) const {
    return Encryption::EncryptionOptions{
        .schema =
            FuzzedObject<Encryption::EncryptionOptions::Schema>()(provider),
    };
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_ENCRYPTION_H_
