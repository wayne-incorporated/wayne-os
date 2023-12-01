// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/portal_detector.h"

#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/functional/bind.h>
#include <base/time/time.h>
#include <brillo/http/http_request.h>
#include <brillo/http/mock_connection.h>
#include <brillo/http/mock_transport.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/http_request.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/net/ip_address.h"

using testing::_;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::StrictMock;
using testing::Test;

namespace shill {

namespace {
const char kBadURL[] = "badurl";
const char kInterfaceName[] = "int0";
const char kHttpUrl[] = "http://www.chromium.org";
const char kHttpsUrl[] = "https://www.google.com";
const std::vector<std::string> kFallbackHttpUrls{
    "http://www.google.com/gen_204",
    "http://play.googleapis.com/generate_204",
};
const std::vector<std::string> kFallbackHttpsUrls{
    "http://url1.com/gen204",
    "http://url2.com/gen204",
};
const IPAddress kIpAddress = *IPAddress::CreateFromString("1.2.3.4");
const char kDNSServer0[] = "8.8.8.8";
const char kDNSServer1[] = "8.8.4.4";
const char* const kDNSServers[] = {kDNSServer0, kDNSServer1};

class MockHttpRequest : public HttpRequest {
 public:
  MockHttpRequest()
      : HttpRequest(nullptr,
                    kInterfaceName,
                    IPAddress::CreateFromFamily(IPAddress::kFamilyIPv4),
                    {kDNSServer0, kDNSServer1},
                    true) {}
  MockHttpRequest(const MockHttpRequest&) = delete;
  MockHttpRequest& operator=(const MockHttpRequest&) = delete;
  ~MockHttpRequest() = default;

  MOCK_METHOD(
      HttpRequest::Result,
      Start,
      (const std::string&,
       const std::string&,
       const brillo::http::HeaderList&,
       base::OnceCallback<void(std::shared_ptr<brillo::http::Response>)>,
       base::OnceCallback<void(Result)>),
      (override));
};

}  // namespace

MATCHER_P(IsResult, result, "") {
  return (result.http_phase == arg.http_phase &&
          result.http_status == arg.http_status &&
          result.https_phase == arg.https_phase &&
          result.https_status == arg.https_status &&
          result.redirect_url_string == arg.redirect_url_string &&
          result.probe_url_string == arg.probe_url_string);
}

class PortalDetectorTest : public Test {
 public:
  PortalDetectorTest()
      : transport_(std::make_shared<brillo::http::MockTransport>()),
        brillo_connection_(
            std::make_shared<brillo::http::MockConnection>(transport_)),
        portal_detector_(
            new PortalDetector(&dispatcher_,
                               MakeProbingConfiguration(),
                               callback_target_.result_callback())),
        interface_name_(kInterfaceName),
        dns_servers_(kDNSServers, kDNSServers + 2),
        http_request_(nullptr),
        https_request_(nullptr) {}

  void SetUp() override { EXPECT_EQ(nullptr, portal_detector_->http_request_); }

  void TearDown() override {
    Mock::VerifyAndClearExpectations(&http_request_);
    testing::Mock::VerifyAndClearExpectations(brillo_connection_.get());
    brillo_connection_.reset();
    testing::Mock::VerifyAndClearExpectations(transport_.get());
    transport_.reset();
  }

 protected:
  static const int kNumAttempts;

  class CallbackTarget {
   public:
    CallbackTarget()
        : result_callback_(base::BindRepeating(&CallbackTarget::ResultCallback,
                                               base::Unretained(this))) {}

    MOCK_METHOD(void, ResultCallback, (const PortalDetector::Result&));

    base::RepeatingCallback<void(const PortalDetector::Result&)>&
    result_callback() {
      return result_callback_;
    }

   private:
    base::RepeatingCallback<void(const PortalDetector::Result&)>
        result_callback_;
  };

  void AssignHttpRequest() {
    http_request_ = new StrictMock<MockHttpRequest>();
    https_request_ = new StrictMock<MockHttpRequest>();
    // Passes ownership.
    portal_detector_->http_request_.reset(http_request_);
    portal_detector_->https_request_.reset(https_request_);
  }

  static PortalDetector::ProbingConfiguration MakeProbingConfiguration() {
    PortalDetector::ProbingConfiguration config;
    config.portal_http_url = kHttpUrl;
    config.portal_https_url = kHttpsUrl;
    config.portal_fallback_http_urls = kFallbackHttpUrls;
    config.portal_fallback_https_urls = kFallbackHttpsUrls;
    return config;
  }

  bool StartPortalRequest(base::TimeDelta delay = base::TimeDelta()) {
    if (!portal_detector_->Start(kInterfaceName, kIpAddress,
                                 {kDNSServer0, kDNSServer1}, "tag", delay)) {
      return false;
    }
    AssignHttpRequest();
    return true;
  }

  bool RestartPortalRequest() {
    if (!portal_detector_->Restart(kInterfaceName, kIpAddress,
                                   {kDNSServer0, kDNSServer1}, "tag")) {
      return false;
    }
    AssignHttpRequest();
    return true;
  }

  void StartTrialTask() {
    EXPECT_CALL(*http_request(), Start(_, _, _, _, _))
        .WillOnce(Return(HttpRequest::kResultInProgress));
    EXPECT_CALL(*https_request(), Start(_, _, _, _, _))
        .WillOnce(Return(HttpRequest::kResultInProgress));
    portal_detector()->StartTrialTask();
  }

  MockHttpRequest* http_request() { return http_request_; }
  MockHttpRequest* https_request() { return https_request_; }
  PortalDetector* portal_detector() { return portal_detector_.get(); }
  MockEventDispatcher& dispatcher() { return dispatcher_; }
  CallbackTarget& callback_target() { return callback_target_; }
  brillo::http::MockConnection* brillo_connection() {
    return brillo_connection_.get();
  }

  void ExpectReset() {
    EXPECT_EQ(0, portal_detector_->attempt_count_);
    EXPECT_TRUE(callback_target_.result_callback() ==
                portal_detector_->portal_result_callback_);
    ExpectCleanupTrial();
  }

  void ExpectCleanupTrial() {
    EXPECT_FALSE(portal_detector_->IsInProgress());
    EXPECT_EQ(nullptr, portal_detector_->http_request_);
    EXPECT_EQ(nullptr, portal_detector_->https_request_);
  }

  void StartAttempt() {
    EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta()));
    EXPECT_TRUE(StartPortalRequest());
    StartTrialTask();
  }

  void ExpectRequestSuccessWithStatus(int status_code, bool is_http) {
    EXPECT_CALL(*brillo_connection_, GetResponseStatusCode())
        .WillOnce(Return(status_code));

    auto response =
        std::make_shared<brillo::http::Response>(brillo_connection_);
    if (is_http)
      portal_detector_->HttpRequestSuccessCallback(response);
    else
      portal_detector_->HttpsRequestSuccessCallback(response);
  }

 protected:
  StrictMock<MockEventDispatcher> dispatcher_;
  std::shared_ptr<brillo::http::MockTransport> transport_;
  std::shared_ptr<brillo::http::MockConnection> brillo_connection_;
  CallbackTarget callback_target_;
  std::unique_ptr<PortalDetector> portal_detector_;
  const std::string interface_name_;
  std::vector<std::string> dns_servers_;
  MockHttpRequest* http_request_;
  MockHttpRequest* https_request_;
};

// static
const int PortalDetectorTest::kNumAttempts = 0;

TEST_F(PortalDetectorTest, Constructor) {
  ExpectReset();
}

TEST_F(PortalDetectorTest, InvalidURL) {
  EXPECT_FALSE(portal_detector()->IsInProgress());
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta())).Times(0);
  auto probing_configuration = MakeProbingConfiguration();
  probing_configuration.portal_http_url = kBadURL;
  portal_detector()->set_probing_configuration_for_testing(
      probing_configuration);
  EXPECT_FALSE(StartPortalRequest());
  ExpectReset();

  EXPECT_FALSE(portal_detector()->IsInProgress());
}

TEST_F(PortalDetectorTest, IsInProgress) {
  // Before the trial is started, should not be active.
  EXPECT_FALSE(portal_detector()->IsInProgress());

  // Once the trial is started, IsInProgress should return true.
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta()));
  EXPECT_TRUE(StartPortalRequest());

  StartTrialTask();
  EXPECT_TRUE(portal_detector()->IsInProgress());

  // Finish the trial, IsInProgress should return false.
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kFailure;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kSuccess;
  portal_detector()->CompleteTrial(result);
  ExpectCleanupTrial();
}

TEST_F(PortalDetectorTest, HttpStartAttemptFailed) {
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta()));
  EXPECT_TRUE(StartPortalRequest());

  // Expect that the HTTP request will be started -- return failure.
  EXPECT_CALL(*http_request(), Start(_, _, _, _, _))
      .WillOnce(Return(HttpRequest::kResultDNSFailure));
  EXPECT_CALL(*https_request(), Start(_, _, _, _, _)).Times(0);
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta())).Times(0);

  // Expect a non-final failure to be relayed to the caller.
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kDNS,
  result.http_status = PortalDetector::Status::kFailure;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.num_attempts = kNumAttempts;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result)));

  portal_detector()->StartTrialTask();
  ExpectCleanupTrial();
}

TEST_F(PortalDetectorTest, HttpsStartAttemptFailed) {
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta()));
  EXPECT_TRUE(StartPortalRequest());

  // Expect that the HTTP request will be started successfully and the
  // HTTPS request will fail to start.
  EXPECT_CALL(*http_request(), Start(_, _, _, _, _))
      .WillOnce(Return(HttpRequest::kResultInProgress));
  EXPECT_CALL(*https_request(), Start(_, _, _, _, _))
      .WillOnce(Return(HttpRequest::kResultDNSFailure));
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta())).Times(0);

  // Expect PortalDetector will wait for HTTP probe completion.
  EXPECT_CALL(callback_target(), ResultCallback(_)).Times(0);

  portal_detector()->StartTrialTask();
  EXPECT_TRUE(portal_detector()->IsInProgress());
  EXPECT_NE(nullptr, portal_detector_->http_request_);
  EXPECT_NE(nullptr, portal_detector_->https_request_);
  Mock::VerifyAndClearExpectations(&callback_target());

  // Finish the trial, IsInProgress should return false.
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent;
  result.http_status = PortalDetector::Status::kSuccess;
  result.https_phase = PortalDetector::Phase::kContent,
  result.https_status = PortalDetector::Status::kFailure;
  portal_detector()->CompleteTrial(result);
  ExpectCleanupTrial();
}

TEST_F(PortalDetectorTest, GetNextAttemptDelay) {
  EXPECT_EQ(portal_detector()->GetNextAttemptDelay(), base::TimeDelta());

  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, base::TimeDelta()));
  EXPECT_TRUE(StartPortalRequest());

  EXPECT_GT(portal_detector()->GetNextAttemptDelay(), base::TimeDelta());
}

TEST_F(PortalDetectorTest, DelayedAttempt) {
  const auto delay = base::Seconds(123);
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, delay)).Times(1);
  EXPECT_TRUE(StartPortalRequest(delay));
}

TEST_F(PortalDetectorTest, Restart) {
  EXPECT_FALSE(portal_detector()->IsInProgress());

  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, _)).Times(1);
  EXPECT_EQ(portal_detector()->GetNextAttemptDelay(), base::TimeDelta());
  EXPECT_EQ(0, portal_detector()->attempt_count());
  EXPECT_TRUE(StartPortalRequest());
  EXPECT_EQ(portal_detector()->http_url_string_, kHttpUrl);
  EXPECT_EQ(1, portal_detector()->attempt_count());
  Mock::VerifyAndClearExpectations(&dispatcher_);

  auto next_delay = portal_detector()->GetNextAttemptDelay();
  EXPECT_GT(next_delay, base::TimeDelta());
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, _)).Times(1);
  EXPECT_TRUE(RestartPortalRequest());
  EXPECT_EQ(2, portal_detector()->attempt_count());
  Mock::VerifyAndClearExpectations(&dispatcher_);

  portal_detector()->Stop();
  ExpectReset();
}

TEST_F(PortalDetectorTest, AttemptCount) {
  EXPECT_FALSE(portal_detector()->IsInProgress());
  EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, _)).Times(1);
  EXPECT_TRUE(StartPortalRequest());
  EXPECT_EQ(portal_detector()->http_url_string_, kHttpUrl);
  Mock::VerifyAndClearExpectations(&dispatcher_);

  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kDNS,
  result.http_status = PortalDetector::Status::kFailure;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.num_attempts = kNumAttempts;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result))).Times(3);

  std::set<std::string> expected_retry_http_urls(kFallbackHttpUrls.begin(),
                                                 kFallbackHttpUrls.end());
  expected_retry_http_urls.insert(kHttpUrl);

  std::set<std::string> expected_retry_https_urls(kFallbackHttpsUrls.begin(),
                                                  kFallbackHttpsUrls.end());
  expected_retry_https_urls.insert(kHttpsUrl);

  auto last_delay = base::TimeDelta();
  for (int i = 1; i < 4; i++) {
    EXPECT_EQ(i, portal_detector()->attempt_count());
    const auto delay = portal_detector()->GetNextAttemptDelay();
    EXPECT_GT(delay, last_delay);
    EXPECT_CALL(dispatcher(), PostDelayedTask(_, _, _)).Times(1);
    last_delay = delay;
    EXPECT_TRUE(RestartPortalRequest());

    EXPECT_NE(
        expected_retry_http_urls.find(portal_detector()->http_url_string_),
        expected_retry_http_urls.end());
    EXPECT_NE(
        expected_retry_https_urls.find(portal_detector()->https_url_string_),
        expected_retry_https_urls.end());

    portal_detector()->CompleteTrial(result);
    Mock::VerifyAndClearExpectations(&dispatcher_);
  }
  portal_detector()->Stop();
  ExpectReset();
}

TEST_F(PortalDetectorTest, RequestSuccess) {
  StartAttempt();

  // HTTPS probe does not trigger anything (for now)
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kSuccess;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kSuccess;
  result.num_attempts = kNumAttempts;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result))).Times(0);
  EXPECT_TRUE(portal_detector_->IsInProgress());
  EXPECT_NE(nullptr, portal_detector_->http_request_);
  EXPECT_NE(nullptr, portal_detector_->https_request_);
  ExpectRequestSuccessWithStatus(204, false);

  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result)));
  ExpectRequestSuccessWithStatus(204, true);
  ExpectCleanupTrial();
}

TEST_F(PortalDetectorTest, RequestHTTPFailureHTTPSSuccess) {
  StartAttempt();

  // HTTPS probe does not trigger anything (for now)
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kFailure;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kSuccess;
  result.num_attempts = kNumAttempts;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result))).Times(0);
  EXPECT_TRUE(portal_detector_->IsInProgress());
  EXPECT_NE(nullptr, portal_detector_->http_request_);
  EXPECT_NE(nullptr, portal_detector_->https_request_);
  ExpectRequestSuccessWithStatus(123, true);

  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result)));
  ExpectRequestSuccessWithStatus(204, false);
  ExpectCleanupTrial();
}

TEST_F(PortalDetectorTest, RequestFail) {
  StartAttempt();

  // HTTPS probe does not trigger anything (for now)
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kFailure;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.num_attempts = kNumAttempts;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result))).Times(0);
  EXPECT_TRUE(portal_detector_->IsInProgress());
  EXPECT_NE(nullptr, portal_detector_->http_request_);
  EXPECT_NE(nullptr, portal_detector_->https_request_);
  ExpectRequestSuccessWithStatus(123, false);

  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result)));
  ExpectRequestSuccessWithStatus(123, true);
  ExpectCleanupTrial();
}

TEST_F(PortalDetectorTest, RequestRedirect) {
  StartAttempt();

  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kRedirect;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.redirect_url_string = kHttpUrl;
  result.probe_url_string = kHttpUrl;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result))).Times(0);
  EXPECT_TRUE(portal_detector_->IsInProgress());
  EXPECT_NE(nullptr, portal_detector_->http_request_);
  EXPECT_NE(nullptr, portal_detector_->https_request_);
  ExpectRequestSuccessWithStatus(123, false);

  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result)));
  EXPECT_CALL(*brillo_connection(), GetResponseHeader("Location"))
      .WillOnce(Return(kHttpUrl));
  ExpectRequestSuccessWithStatus(302, true);
  ExpectCleanupTrial();
}

TEST_F(PortalDetectorTest, RequestTempRedirect) {
  StartAttempt();

  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kRedirect;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.redirect_url_string = kHttpUrl;
  result.probe_url_string = kHttpUrl;
  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result))).Times(0);
  EXPECT_TRUE(portal_detector_->IsInProgress());
  EXPECT_NE(nullptr, portal_detector_->http_request_);
  EXPECT_NE(nullptr, portal_detector_->https_request_);
  ExpectRequestSuccessWithStatus(123, false);

  EXPECT_CALL(callback_target(), ResultCallback(IsResult(result)));
  EXPECT_CALL(*brillo_connection(), GetResponseHeader("Location"))
      .WillOnce(Return(kHttpUrl));
  ExpectRequestSuccessWithStatus(307, true);
  ExpectCleanupTrial();
}

TEST_F(PortalDetectorTest, PhaseToString) {
  struct {
    PortalDetector::Phase phase;
    std::string expected_name;
  } test_cases[] = {
      {PortalDetector::Phase::kConnection, "Connection"},
      {PortalDetector::Phase::kDNS, "DNS"},
      {PortalDetector::Phase::kHTTP, "HTTP"},
      {PortalDetector::Phase::kContent, "Content"},
      {PortalDetector::Phase::kUnknown, "Unknown"},
  };

  for (const auto& t : test_cases) {
    EXPECT_EQ(t.expected_name, PortalDetector::PhaseToString(t.phase));
  }
}

TEST_F(PortalDetectorTest, StatusToString) {
  struct {
    PortalDetector::Status status;
    std::string expected_name;
  } test_cases[] = {
      {PortalDetector::Status::kSuccess, "Success"},
      {PortalDetector::Status::kTimeout, "Timeout"},
      {PortalDetector::Status::kRedirect, "Redirect"},
      {PortalDetector::Status::kFailure, "Failure"},
  };

  for (const auto& t : test_cases) {
    EXPECT_EQ(t.expected_name, PortalDetector::StatusToString(t.status));
  }
}

TEST_F(PortalDetectorTest, PickProbeUrlTest) {
  const std::string url1 = "http://www.url1.com";
  const std::string url2 = "http://www.url2.com";
  const std::string url3 = "http://www.url3.com";
  const std::set<std::string> all_urls = {url1, url2, url3};
  std::set<std::string> all_found_urls;

  EXPECT_EQ(url1, portal_detector_->PickProbeUrl(url1, {}));
  EXPECT_EQ(url1, portal_detector_->PickProbeUrl(url1, {url2, url3}));

  // The loop index starts at 1 to force a non-zero |attempt_count_| and to
  // force using the fallback list.
  for (int i = 1; i < 100; i++) {
    portal_detector_->attempt_count_ = i;
    EXPECT_EQ(portal_detector_->PickProbeUrl(url1, {}), url1);

    const auto found = portal_detector_->PickProbeUrl(url1, {url2, url3});
    all_found_urls.insert(found);
    EXPECT_NE(all_urls.find(found), all_urls.end());
  }
  // Probability this assert fails = 3 * 1/3 ^ 99 + 3 * 2/3 ^ 99
  EXPECT_EQ(all_urls, all_found_urls);
}

}  // namespace shill
