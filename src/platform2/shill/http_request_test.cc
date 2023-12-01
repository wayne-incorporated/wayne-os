// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/http_request.h"

#include <netinet/in.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <brillo/http/mock_connection.h>
#include <brillo/http/mock_transport.h>
#include <brillo/mime_utils.h>
#include <brillo/streams/mock_stream.h>
#include <curl/curl.h>
#include <gtest/gtest.h>

#include "shill/http_url.h"
#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_dns_client.h"
#include "shill/mock_manager.h"
#include "shill/net/ip_address.h"
#include "shill/net/mock_sockets.h"
#include "shill/test_event_dispatcher.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::StrictMock;
using ::testing::Test;
using ::testing::Unused;
using ::testing::WithArg;

namespace shill {

namespace {
const char kTextSiteName[] = "www.chromium.org";
const char kTextURL[] = "http://www.chromium.org/path/to/resource";
const char kNumericURL[] = "http://10.1.1.1";
const char kInterfaceName[] = "int0";
const char kLoggingTag[] = "int0 IPv4 attempt=1";
const char kDNSServer0[] = "8.8.8.8";
const char kDNSServer1[] = "8.8.4.4";
const char* const kDNSServers[] = {kDNSServer0, kDNSServer1};
const char kServerAddress[] = "10.1.1.1";
}  // namespace

MATCHER_P(IsIPAddress, address, "") {
  const auto ip_address = IPAddress::CreateFromString(address);
  CHECK(ip_address.has_value());
  return ip_address.Equals(arg);
}

MATCHER_P(ByteStringMatches, byte_string, "") {
  return byte_string.Equals(arg);
}

MATCHER_P(CallbackEq, callback, "") {
  return arg.Equals(callback);
}

class HttpRequestTest : public Test {
 public:
  HttpRequestTest()
      : interface_name_(kInterfaceName),
        dns_list_(kDNSServers, kDNSServers + 2),
        dns_client_(new StrictMock<MockDnsClient>()),
        transport_(std::make_shared<brillo::http::MockTransport>()),
        brillo_connection_(
            std::make_shared<brillo::http::MockConnection>(transport_)),
        manager_(&control_, &dispatcher_, nullptr),
        device_info_(new NiceMock<MockDeviceInfo>(&manager_)) {}

 protected:
  class CallbackTarget {
   public:
    MOCK_METHOD(void,
                RequestSuccessCallTarget,
                (std::shared_ptr<brillo::http::Response>));
    MOCK_METHOD(void, RequestErrorCallTarget, (HttpRequest::Result));

    base::OnceCallback<void(std::shared_ptr<brillo::http::Response>)>
    request_success_callback() {
      return base::BindOnce(&CallbackTarget::RequestSuccessCallTarget,
                            base::Unretained(this));
    }

    base::OnceCallback<void(HttpRequest::Result)> request_error_callback() {
      return base::BindOnce(&CallbackTarget::RequestErrorCallTarget,
                            base::Unretained(this));
    }
  };

  void SetUp() override {
    request_.reset(
        new HttpRequest(&dispatcher_, interface_name_,
                        IPAddress::CreateFromFamily(IPAddress::kFamilyIPv4),
                        {kDNSServer0, kDNSServer1}, true));
    // Passes ownership.
    request_->dns_client_.reset(dns_client_);
    request_->transport_ = transport_;
  }
  void TearDown() override {
    if (request_->is_running_) {
      ExpectStop();

      // Subtle: Make sure the finalization of the request happens while our
      // expectations are still active.
      request_.reset();
    }
    testing::Mock::VerifyAndClearExpectations(brillo_connection_.get());
    brillo_connection_.reset();
    testing::Mock::VerifyAndClearExpectations(transport_.get());
    transport_.reset();
  }
  HttpRequest* request() { return request_.get(); }

  // Expectations
  void ExpectReset() {
    EXPECT_TRUE(request_->request_error_callback_.is_null());
    EXPECT_TRUE(request_->request_success_callback_.is_null());
    EXPECT_FALSE(request_->dns_client_callback_.is_null());
    EXPECT_EQ(dns_client_, request_->dns_client_.get());
    EXPECT_TRUE(request_->server_hostname_.empty());
    EXPECT_FALSE(request_->is_running_);
  }
  void ExpectStop() { EXPECT_CALL(*dns_client_, Stop()).Times(AtLeast(1)); }
  void ExpectDNSRequest(const std::string& host, bool return_value) {
    EXPECT_CALL(*dns_client_, Start(_, StrEq(host), _))
        .WillOnce(Return(return_value));
  }
  void ExpectRequestErrorCallback(HttpRequest::Result result) {
    EXPECT_CALL(target_, RequestErrorCallTarget(result));
  }
  void InvokeResultVerify(std::shared_ptr<brillo::http::Response> response) {
    EXPECT_CALL(*brillo_connection_, GetResponseStatusCode())
        .WillOnce(Return(brillo::http::status_code::Partial));
    EXPECT_EQ(brillo::http::status_code::Partial, response->GetStatusCode());

    EXPECT_CALL(*brillo_connection_, GetResponseStatusText())
        .WillOnce(Return("Partial completion"));
    EXPECT_EQ("Partial completion", response->GetStatusText());

    EXPECT_CALL(*brillo_connection_,
                GetResponseHeader(brillo::http::response_header::kContentType))
        .WillOnce(Return(brillo::mime::text::kHtml));
    EXPECT_EQ(brillo::mime::text::kHtml, response->GetContentType());

    EXPECT_EQ(expected_response_, response->ExtractDataAsString());
  }
  void ExpectRequestSuccessCallback(const std::string& resp_data) {
    expected_response_ = resp_data;
    EXPECT_CALL(target_, RequestSuccessCallTarget(_))
        .WillOnce(Invoke(this, &HttpRequestTest::InvokeResultVerify));
  }
  void GetDNSResultFailure(const std::string& error_msg) {
    Error error(Error::kOperationFailed, error_msg);
    IPAddress address = IPAddress::CreateFromFamily(IPAddress::kFamilyUnknown);
    request_->GetDNSResult(error, address);
  }
  void GetDNSResultSuccess(const IPAddress& address) {
    Error error;
    request_->GetDNSResult(error, address);
  }
  HttpRequest::Result StartRequest(const std::string& url) {
    return request_->Start(kLoggingTag, url, {},
                           target_.request_success_callback(),
                           target_.request_error_callback());
  }
  void ExpectCreateConnection(const std::string& url) {
    EXPECT_CALL(
        *transport_,
        CreateConnection(url, brillo::http::request_type::kGet, _, "", "", _))
        .WillOnce(Return(brillo_connection_));
  }
  void ExpectResolveHostToIp(const std::string& host,
                             int port,
                             const std::string& path) {
    EXPECT_CALL(*transport_, ResolveHostToIp(host, port, path));
  }
  void FinishRequestAsyncSuccess(
      brillo::http::SuccessCallback success_callback) {
    auto read_data = [this](void* buffer, Unused, size_t* read,
                            Unused) -> bool {
      memcpy(buffer, resp_data_.data(), resp_data_.size());
      *read = resp_data_.size();
      return true;
    };

    auto mock_stream = std::make_unique<brillo::MockStream>();
    EXPECT_CALL(*mock_stream, ReadBlocking(_, _, _, _))
        .WillOnce(Invoke(read_data))
        .WillOnce(DoAll(SetArgPointee<2>(0), Return(true)));

    EXPECT_CALL(*brillo_connection_, MockExtractDataStream(_))
        .WillOnce(Return(mock_stream.release()));
    auto resp = std::make_unique<brillo::http::Response>(brillo_connection_);
    // request_id_ has not yet been set. Pass -1 to match default value.
    std::move(success_callback).Run(-1, std::move(resp));
  }
  void FinishRequestAsyncFail(brillo::http::ErrorCallback error_callback) {
    brillo::ErrorPtr error;
    brillo::Error::AddTo(&error, FROM_HERE, "curl_easy_error",
                         base::NumberToString(CURLE_COULDNT_CONNECT), "");
    // request_id_ has not yet been set. Pass -1 to match default value.
    std::move(error_callback).Run(-1, error.get());
  }
  void ExpectFinishRequestAsyncSuccess(const std::string& resp_data) {
    resp_data_ = resp_data;
    EXPECT_CALL(*brillo_connection_, FinishRequestAsync(_, _))
        .WillOnce(WithArg<0>([this](auto callback) {
          FinishRequestAsyncSuccess(std::move(callback));
          return 0;
        }));
  }
  void ExpectFinishRequestAsyncFail() {
    EXPECT_CALL(*brillo_connection_, FinishRequestAsync(_, _))
        .WillOnce(WithArg<1>([this](auto callback) {
          FinishRequestAsyncFail(std::move(callback));
          return 0;
        }));
  }

 private:
  const std::string interface_name_;
  std::vector<std::string> dns_list_;
  // Owned by the HttpRequest, but tracked here for EXPECT().
  StrictMock<MockDnsClient>* dns_client_;
  std::shared_ptr<brillo::http::MockTransport> transport_;
  std::shared_ptr<brillo::http::MockConnection> brillo_connection_;
  EventDispatcherForTest dispatcher_;
  MockControl control_;
  MockManager manager_;
  std::unique_ptr<MockDeviceInfo> device_info_;
  std::unique_ptr<HttpRequest> request_;
  StrictMock<CallbackTarget> target_;
  std::string expected_response_;
  std::string resp_data_;
};

TEST_F(HttpRequestTest, Constructor) {
  ExpectReset();
}

TEST_F(HttpRequestTest, NumericRequestSuccess) {
  const std::string resp{"Sample response."};
  ExpectRequestSuccessCallback(resp);

  ExpectCreateConnection(kNumericURL);
  ExpectFinishRequestAsyncSuccess(resp);

  ExpectStop();
  EXPECT_EQ(HttpRequest::kResultInProgress, StartRequest(kNumericURL));
  ExpectReset();
}

TEST_F(HttpRequestTest, RequestFail) {
  ExpectRequestErrorCallback(HttpRequest::kResultConnectionFailure);

  ExpectCreateConnection(kNumericURL);
  ExpectFinishRequestAsyncFail();

  ExpectStop();
  EXPECT_EQ(HttpRequest::kResultInProgress, StartRequest(kNumericURL));
  ExpectReset();
}

TEST_F(HttpRequestTest, TextRequestSuccess) {
  ExpectDNSRequest(kTextSiteName, true);

  const std::string resp{"Sample response."};
  ExpectRequestSuccessCallback(resp);
  HttpUrl url;
  EXPECT_TRUE(url.ParseFromString(kTextURL));
  ExpectResolveHostToIp(url.host(), url.port(), kServerAddress);
  ExpectCreateConnection(kTextURL);
  ExpectFinishRequestAsyncSuccess(resp);

  ExpectStop();
  EXPECT_EQ(HttpRequest::kResultInProgress, StartRequest(kTextURL));
  const auto addr = IPAddress::CreateFromString(kServerAddress);
  CHECK(addr.has_value());
  GetDNSResultSuccess(*addr);
  ExpectReset();
}

TEST_F(HttpRequestTest, FailDNSStart) {
  ExpectDNSRequest(kTextSiteName, false);
  ExpectStop();
  EXPECT_EQ(HttpRequest::kResultDNSFailure, StartRequest(kTextURL));
  ExpectReset();
}

TEST_F(HttpRequestTest, FailDNSFailure) {
  ExpectDNSRequest(kTextSiteName, true);
  EXPECT_EQ(HttpRequest::kResultInProgress, StartRequest(kTextURL));
  ExpectRequestErrorCallback(HttpRequest::kResultDNSFailure);
  ExpectStop();
  GetDNSResultFailure(DnsClient::kErrorNoData);
  ExpectReset();
}

TEST_F(HttpRequestTest, FailDNSTimeout) {
  ExpectDNSRequest(kTextSiteName, true);
  EXPECT_EQ(HttpRequest::kResultInProgress, StartRequest(kTextURL));
  ExpectRequestErrorCallback(HttpRequest::kResultDNSTimeout);
  ExpectStop();
  const std::string error(DnsClient::kErrorTimedOut);
  GetDNSResultFailure(error);
  ExpectReset();
}

}  // namespace shill
