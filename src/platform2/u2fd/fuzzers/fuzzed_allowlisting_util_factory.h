// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_FUZZERS_FUZZED_ALLOWLISTING_UTIL_FACTORY_H_
#define U2FD_FUZZERS_FUZZED_ALLOWLISTING_UTIL_FACTORY_H_

#include <memory>
#include <optional>

#include <attestation/proto_bindings/interface.pb.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "u2fd/allowlisting_util.h"

namespace u2f {

// The |FuzzedDataProvider| and this class must outlive the created
// |AllowlistingUtil|.
class FuzzedAllowlistingUtilFactory {
 public:
  explicit FuzzedAllowlistingUtilFactory(FuzzedDataProvider* data_provider)
      : data_provider_(data_provider) {}

  std::unique_ptr<u2f::AllowlistingUtil> CreateAllowlistingUtil();

 private:
  std::optional<attestation::GetCertifiedNvIndexReply> GetCertifiedG2fCert(
      int g2f_cert_size);

  FuzzedDataProvider* const data_provider_;
};

}  // namespace u2f

#endif  // U2FD_FUZZERS_FUZZED_ALLOWLISTING_UTIL_FACTORY_H_
