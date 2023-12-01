// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_HTTP_MOCK_TRANSPORT_H_
#define LIBBRILLO_BRILLO_HTTP_MOCK_TRANSPORT_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/location.h>
#include <brillo/http/http_transport.h>
#include <gmock/gmock.h>

namespace brillo {
namespace http {

class MockTransport : public Transport {
 public:
  MockTransport() = default;
  MockTransport(const MockTransport&) = delete;
  MockTransport& operator=(const MockTransport&) = delete;

  MOCK_METHOD(std::shared_ptr<Connection>,
              CreateConnection,
              (const std::string&,
               const std::string&,
               const HeaderList&,
               const std::string&,
               const std::string&,
               brillo::ErrorPtr*),
              (override));
  MOCK_METHOD(void,
              RunCallbackAsync,
              (const base::Location&, base::OnceClosure),
              (override));
  MOCK_METHOD(RequestID,
              StartAsyncTransfer,
              (Connection*, SuccessCallback, ErrorCallback),
              (override));
  MOCK_METHOD(bool, CancelRequest, (RequestID), (override));
  MOCK_METHOD(void, SetDefaultTimeout, (base::TimeDelta), (override));
  MOCK_METHOD(void, SetLocalIpAddress, (const std::string&), (override));
  MOCK_METHOD(void,
              SetDnsServers,
              (const std::vector<std::string>&),
              (override));
  MOCK_METHOD(void, SetDnsInterface, (const std::string&), (override));
  MOCK_METHOD(void, SetDnsLocalIPv4Address, (const std::string&), (override));
  MOCK_METHOD(void, SetDnsLocalIPv6Address, (const std::string&), (override));
  MOCK_METHOD(void, UseDefaultCertificate, (), (override));
  MOCK_METHOD(void, UseCustomCertificate, (Certificate), (override));
  MOCK_METHOD(void,
              ResolveHostToIp,
              (const std::string&, uint16_t, const std::string&),
              (override));

  MOCK_METHOD(void, SetBufferSize, (std::optional<int>), (override));
  MOCK_METHOD(void, SetUploadBufferSize, (std::optional<int>), (override));

 protected:
  MOCK_METHOD(void, ClearHost, (), (override));
};

}  // namespace http
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_HTTP_MOCK_TRANSPORT_H_
