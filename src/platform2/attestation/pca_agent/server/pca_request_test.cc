// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/pca_agent/server/pca_request.h"

#include <memory>
#include <utility>

#include <base/time/time.h>
#include <brillo/errors/error.h>
#include <brillo/http/http_connection_fake.h>
#include <brillo/mime_utils.h>
#include <brillo/streams/memory_stream.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "attestation/pca_agent/server/fake_transport_factory.h"
#include "attestation/pca_agent/server/mock_pca_http_utils.h"
#include "attestation/pca_agent/server/response_with_verifier.h"

namespace {

using ::testing::ByRef;
using ::testing::Types;
using ::testing::Unused;

constexpr char kFakeUrl[] = "fake.url.org";
constexpr char kFakeRequest[] = "fake request";
constexpr char kFakeResponse[] = "fake response";
constexpr char kFakeErrMessage[] = "a tactical error";
constexpr char kFakeHandlerName[] = "testing";

constexpr char kFakeProxy1[] = "https://fake-proxy1:8000";
constexpr char kFakeProxy2[] = "https://fake-proxy2:8000";
constexpr char kFakeProxy3[] = "https://fake-proxy3:8000";

void FakeMethodHandler(int status_code,
                       const brillo::http::fake::ServerRequest& request,
                       brillo::http::fake::ServerResponse* response) {
  response->ReplyText(
      status_code,
      status_code == brillo::http::status_code::Ok ? kFakeResponse : "",
      brillo::mime::text::kPlain);
}

}  // namespace

namespace attestation {
namespace pca_agent {

template <typename ReplyType>
class PcaRequestTest : public ::testing::Test {
 protected:
  void SetUp() override {
    EXPECT_CALL(mock_pca_http_utils_, GetChromeProxyServersAsync(_, _))
        .WillRepeatedly([this](Unused, auto callback) {
          std::move(callback).Run(proxy_success_, proxy_servers_);
        });
    request_ = MakePcaRequest();
  }

  scoped_refptr<PcaRequest<ReplyType>> MakePcaRequest() {
    // Sets up the verifier. See |Verify| below. Here we choose lambda over
    // base::Bind.
    auto v = [this](const ReplyType& reply) { this->Verify(reply); };
    auto response = MakeResponseWithVerifier<ReplyType>(v);
    auto request = new PcaRequest<ReplyType>(kFakeHandlerName, kFakeUrl,
                                             kFakeRequest, std::move(response));

    // testing objects injected to the request.
    request->set_transport_factory_for_testing(&fake_trasport_factory_);
    request->set_pca_http_utils_for_testing(&mock_pca_http_utils_);
    return request;
  }

  // Sets the expected result to be returned when getting proxy servers.
  void set_proxy_servers(const std::vector<std::string>& proxy_servers) {
    proxy_servers_ = proxy_servers;
  }

  // Checks the invariant of the reply -- When STATUS_SUCCESS, we also make sure
  // the response is set.
  void Verify(const ReplyType& reply) {
    EXPECT_EQ(reply.status(), expected_attestation_status_);
    if (expected_attestation_status_ == STATUS_SUCCESS) {
      EXPECT_EQ(reply.response(), std::string(kFakeResponse));
    }
  }

  // Mock/fake objects.
  FakeTransportFactory fake_trasport_factory_;
  MockPcaHttpUtils mock_pca_http_utils_;

  // Expected return value for getting proxy servers.
  bool proxy_success_{true};
  std::vector<std::string> proxy_servers_;

  // Expected result status.
  AttestationStatus expected_attestation_status_{STATUS_SUCCESS};

  // The request under test.
  scoped_refptr<PcaRequest<ReplyType>> request_;
};

using ReplyTypes = testing::Types<EnrollReply, GetCertificateReply>;
TYPED_TEST_SUITE(PcaRequestTest, ReplyTypes);

TYPED_TEST(PcaRequestTest, SuccessNoProxy) {
  this->expected_attestation_status_ = STATUS_SUCCESS;
  this->fake_trasport_factory_.get_fake_transport(brillo::http::kDirectProxy)
      ->AddHandler(kFakeUrl, brillo::http::request_type::kPost,
                   base::BindRepeating(FakeMethodHandler,
                                       brillo::http::status_code::Ok));
  this->request_->SendRequest();
}

TYPED_TEST(PcaRequestTest, SuccessFailedToGetProxy) {
  this->expected_attestation_status_ = STATUS_SUCCESS;
  this->proxy_success_ = false;
  this->fake_trasport_factory_.get_fake_transport(brillo::http::kDirectProxy)
      ->AddHandler(kFakeUrl, brillo::http::request_type::kPost,
                   base::BindRepeating(FakeMethodHandler,
                                       brillo::http::status_code::Ok));
  this->request_->SendRequest();
}

TYPED_TEST(PcaRequestTest, SuccessSecondProxy) {
  this->expected_attestation_status_ = STATUS_SUCCESS;
  this->set_proxy_servers({kFakeProxy1, kFakeProxy2, kFakeProxy3});
  this->fake_trasport_factory_.get_fake_transport(kFakeProxy1)
      ->AddHandler(
          kFakeUrl, brillo::http::request_type::kPost,
          base::BindRepeating(FakeMethodHandler,
                              brillo::http::status_code::InternalServerError));
  this->fake_trasport_factory_.get_fake_transport(kFakeProxy2)
      ->AddHandler(kFakeUrl, brillo::http::request_type::kPost,
                   base::BindRepeating(FakeMethodHandler,
                                       brillo::http::status_code::Ok));
  auto not_reached = [](const brillo::http::fake::ServerRequest& request,
                        brillo::http::fake::ServerResponse* response) {
    ASSERT_FALSE("Should not be reached.");
  };
  this->fake_trasport_factory_.get_fake_transport(kFakeProxy3)
      ->AddHandler(kFakeUrl, brillo::http::request_type::kPost,
                   base::BindRepeating(not_reached));
  this->request_->SendRequest();
}

TYPED_TEST(PcaRequestTest, FailedConnectionError) {
  this->expected_attestation_status_ = STATUS_CA_NOT_AVAILABLE;
  brillo::ErrorPtr error;
  brillo::Error::AddTo(&error, FROM_HERE, "", "", kFakeErrMessage);
  this->fake_trasport_factory_.get_fake_transport(kFakeProxy1)
      ->SetCreateConnectionError(std::move(error));
  this->request_->SendRequest();
}

TYPED_TEST(PcaRequestTest, FailedAllProxies) {
  this->expected_attestation_status_ = STATUS_CA_NOT_AVAILABLE;
  this->set_proxy_servers({kFakeProxy1, kFakeProxy2, kFakeProxy3});
  this->fake_trasport_factory_.get_fake_transport(kFakeProxy1)
      ->AddHandler(
          kFakeUrl, brillo::http::request_type::kPost,
          base::BindRepeating(FakeMethodHandler,
                              brillo::http::status_code::InternalServerError));
  brillo::ErrorPtr error;
  brillo::Error::AddTo(&error, FROM_HERE, "", "", kFakeErrMessage);
  this->fake_trasport_factory_.get_fake_transport(kFakeProxy2)
      ->SetCreateConnectionError(std::move(error));
  this->fake_trasport_factory_.get_fake_transport(kFakeProxy3)
      ->AddHandler(
          kFakeUrl, brillo::http::request_type::kPost,
          base::BindRepeating(FakeMethodHandler,
                              brillo::http::status_code::InternalServerError));
  this->request_->SendRequest();
}

TYPED_TEST(PcaRequestTest, FailedNotSupported) {
  this->expected_attestation_status_ = STATUS_NOT_SUPPORTED;
  // Sets the status code to partial to 'Partial`, which should recognized as an
  // unsupported HTTP status code.
  this->fake_trasport_factory_.get_fake_transport(brillo::http::kDirectProxy)
      ->AddHandler(kFakeUrl, brillo::http::request_type::kPost,
                   base::BindRepeating(FakeMethodHandler,
                                       brillo::http::status_code::Partial));
  this->request_->SendRequest();
}

}  // namespace pca_agent
}  // namespace attestation
