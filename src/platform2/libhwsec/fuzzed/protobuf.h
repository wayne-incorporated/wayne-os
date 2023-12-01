// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_PROTOBUF_H_
#define LIBHWSEC_FUZZED_PROTOBUF_H_

#include <string>
#include <type_traits>

#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <google/protobuf/message.h>
#include <libhwsec-foundation/fuzzers/fuzzed_proto_generator.h>

#include "libhwsec/fuzzed/basic_objects.h"

namespace hwsec {

// Generates fuzzed protobuf.
template <typename T>
struct FuzzedObject<
    T,
    std::enable_if_t<std::is_base_of_v<google::protobuf::Message, T>>> {
  T operator()(FuzzedDataProvider& provider) const {
    T result;
    result.ParseFromString(brillo::BlobToString(
        hwsec_foundation::FuzzedProtoGenerator(provider).Generate()));
    return result;
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_PROTOBUF_H_
