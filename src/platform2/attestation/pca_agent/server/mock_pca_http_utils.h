// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_PCA_AGENT_SERVER_MOCK_PCA_HTTP_UTILS_H_
#define ATTESTATION_PCA_AGENT_SERVER_MOCK_PCA_HTTP_UTILS_H_

#include "attestation/pca_agent/server/pca_http_utils.h"

#include <string>

#include <gmock/gmock.h>

namespace attestation {
namespace pca_agent {

class MockPcaHttpUtils : public PcaHttpUtils {
 public:
  MockPcaHttpUtils() = default;
  MockPcaHttpUtils(const MockPcaHttpUtils&) = delete;
  MockPcaHttpUtils& operator=(const MockPcaHttpUtils&) = delete;

  ~MockPcaHttpUtils() override = default;

  MOCK_METHOD(void,
              GetChromeProxyServersAsync,
              (const std::string&, brillo::http::GetChromeProxyServersCallback),
              (override));
};

}  // namespace pca_agent
}  // namespace attestation

#endif  // ATTESTATION_PCA_AGENT_SERVER_MOCK_PCA_HTTP_UTILS_H_
