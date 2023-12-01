// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_BASE_H_
#define HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_BASE_H_

#include <utility>

#include "hwsec-test-utils/common/openssl_utility.h"

namespace hwsec_test_utils {
namespace fake_pca_agent {

// Provides 4-stage interfaces that accomplish a fake PCA request handling. They
// are:
// 1. Proprocess: process the |RequestType| into OpenSSL-friendly or
// TSS-library-friendly structure, or any other data conversion of which the
// product is used in the following stages.
// 2. Verify: Perform the crypto operations to verify if the coming
// |RequestType| provides legit proof.
// 3. Generate: Issue a fake certificate and convert it so the certificate is
// ready for output.
// 4. Write: write the generated data.
//
// The construction of this base class takes a instance of |RequestType| and
// during the write stage, the output is written to an output parameter of
// |ResponseType*| type. Note that this class itself or any subclass of it
// doesn't implement any complex program flow and the consumer is responsible
// for calling them in sequence.
template <typename RequestType, typename ResponseType>
class PcaBase {
 public:
  PcaBase() = delete;
  explicit PcaBase(RequestType request) : request_(std::move(request)) {
    InitializeOpenSSL();
  }
  virtual ~PcaBase() = default;

  // Not copyable or movable.
  PcaBase(const PcaBase&) = delete;
  PcaBase& operator=(const PcaBase&) = delete;
  PcaBase(PcaBase&&) = delete;
  PcaBase& operator=(PcaBase&&) = delete;

  // 4-stage methods.
  virtual bool Preprocess() = 0;
  virtual bool Verify() = 0;
  virtual bool Generate() = 0;
  virtual bool Write(ResponseType* response) = 0;

 protected:
  // Passed in from the constructor.
  const RequestType request_;
};

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_BASE_H_
