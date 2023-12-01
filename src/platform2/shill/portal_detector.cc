// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/portal_detector.h"

#include <ostream>
#include <string>
#include <vector>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/pattern.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/dns_client.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"

namespace {
constexpr char kLinuxUserAgent[] =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/89.0.4389.114 Safari/537.36";
const brillo::http::HeaderList kHeaders{
    {brillo::http::request_header::kUserAgent, kLinuxUserAgent},
};

// Base time interval between two portal detection attempts. Should be doubled
// at every new attempt.
constexpr base::TimeDelta kPortalCheckInterval = base::Seconds(3);
// Min time delay between two portal detection attempts.
constexpr base::TimeDelta kMinPortalCheckDelay = base::Seconds(0);
// Max time interval between two portal detection attempts.
constexpr base::TimeDelta kMaxPortalCheckInterval = base::Minutes(5);
}  // namespace

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kPortal;
static std::string ObjectID(const PortalDetector* pd) {
  return pd->LoggingTag();
}
}  // namespace Logging

PortalDetector::PortalDetector(
    EventDispatcher* dispatcher,
    const ProbingConfiguration& probing_configuration,
    base::RepeatingCallback<void(const Result&)> callback)
    : attempt_count_(0),
      last_attempt_start_time_(),
      dispatcher_(dispatcher),
      weak_ptr_factory_(this),
      portal_result_callback_(callback),
      probing_configuration_(probing_configuration),
      is_active_(false) {}

PortalDetector::~PortalDetector() {
  Stop();
}

const std::string& PortalDetector::PickProbeUrl(
    const std::string& default_url,
    const std::vector<std::string>& fallback_urls) const {
  if (attempt_count_ == 0 || fallback_urls.empty()) {
    return default_url;
  }
  uint32_t index = base::RandInt(0, fallback_urls.size());
  return index < fallback_urls.size() ? fallback_urls[index] : default_url;
}

bool PortalDetector::Restart(const std::string& ifname,
                             const IPAddress& src_address,
                             const std::vector<std::string>& dns_list,
                             const std::string& logging_tag) {
  auto next_delay = GetNextAttemptDelay();
  if (!Start(ifname, src_address, dns_list, logging_tag, next_delay)) {
    LOG(ERROR) << logging_tag << ": Failed to restart";
    return false;
  }
  LOG(INFO) << logging_tag << ": Retrying in " << next_delay;
  return true;
}

bool PortalDetector::Start(const std::string& ifname,
                           const IPAddress& src_address,
                           const std::vector<std::string>& dns_list,
                           const std::string& logging_tag,
                           base::TimeDelta delay) {
  logging_tag_ =
      logging_tag + " " + IPAddress::GetAddressFamilyName(src_address.family());

  SLOG(this, 3) << "In " << __func__;

  // This step is rerun on each attempt, but trying it here will allow
  // Start() to abort on any obviously malformed URL strings.
  HttpUrl http_url, https_url;
  http_url_string_ =
      PickProbeUrl(probing_configuration_.portal_http_url,
                   probing_configuration_.portal_fallback_http_urls);
  https_url_string_ =
      PickProbeUrl(probing_configuration_.portal_https_url,
                   probing_configuration_.portal_fallback_https_urls);
  if (!http_url.ParseFromString(http_url_string_)) {
    LOG(ERROR) << LoggingTag() << ": Failed to parse HTTP probe URL string: "
               << http_url_string_;
    return false;
  }

  if (!https_url.ParseFromString(https_url_string_)) {
    LOG(ERROR) << "Failed to parse HTTPS probe URL string: "
               << https_url_string_;
    return false;
  }

  attempt_count_++;
  // TODO(hugobenichi) Network properties like src address and DNS should be
  // obtained exactly at the time that the trial starts if |delay| > 0.
  http_request_ =
      std::make_unique<HttpRequest>(dispatcher_, ifname, src_address, dns_list);
  // For non-default URLs, allow for secure communication with both Google and
  // non-Google servers.
  bool allow_non_google_https = (https_url_string_ != kDefaultHttpsUrl);
  https_request_ = std::make_unique<HttpRequest>(
      dispatcher_, ifname, src_address, dns_list, allow_non_google_https);
  trial_.Reset(base::BindOnce(&PortalDetector::StartTrialTask,
                              weak_ptr_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(FROM_HERE, trial_.callback(), delay);
  // |last_attempt_start_time_| is calculated based on the current time and
  // |delay|.  This is used to determine when to schedule the next portal
  // detection attempt after this one.
  last_attempt_start_time_ = base::Time::NowFromSystemTime() + delay;

  return true;
}

void PortalDetector::StartTrialTask() {
  LOG(INFO) << LoggingTag() << ": Starting trial";
  HttpRequest::Result http_result = http_request_->Start(
      LoggingTag() + " HTTP probe", http_url_string_, kHeaders,
      base::BindOnce(&PortalDetector::HttpRequestSuccessCallback,
                     weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&PortalDetector::HttpRequestErrorCallback,
                     weak_ptr_factory_.GetWeakPtr()));
  if (http_result != HttpRequest::kResultInProgress) {
    // If the http probe fails to start, complete the trial with a failure
    // Result for https.
    LOG(ERROR) << LoggingTag()
               << ": HTTP probe failed to start. Aborting trial.";
    PortalDetector::Result result;
    result.http_phase = GetPortalPhaseForRequestResult(http_result);
    result.http_status = GetPortalStatusForRequestResult(http_result);
    result.https_phase = PortalDetector::Phase::kContent;
    result.https_status = PortalDetector::Status::kFailure;
    CompleteTrial(result);
    return;
  }

  result_ = std::make_unique<Result>();

  HttpRequest::Result https_result = https_request_->Start(
      LoggingTag() + " HTTPS probe", https_url_string_, kHeaders,
      base::BindOnce(&PortalDetector::HttpsRequestSuccessCallback,
                     weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&PortalDetector::HttpsRequestErrorCallback,
                     weak_ptr_factory_.GetWeakPtr()));
  if (https_result != HttpRequest::kResultInProgress) {
    result_->https_phase = GetPortalPhaseForRequestResult(https_result);
    result_->https_status = GetPortalStatusForRequestResult(https_result);
    LOG(ERROR) << LoggingTag() << ": HTTPS probe failed to start";
    // To find the portal sign-in url, wait for the HTTP probe to complete
    // before completing the trial and calling |portal_result_callback_|.
  }
  is_active_ = true;
}

void PortalDetector::CompleteTrial(Result result) {
  LOG(INFO) << LoggingTag()
            << ": Trial completed. HTTP probe: phase=" << result.http_phase
            << ", status=" << result.http_status
            << ". HTTPS probe: phase=" << result.https_phase
            << ", status=" << result.https_status;
  result.num_attempts = attempt_count_;
  CleanupTrial();
  portal_result_callback_.Run(result);
}

void PortalDetector::CleanupTrial() {
  result_.reset();
  http_request_.reset();
  https_request_.reset();
  is_active_ = false;
}

void PortalDetector::Stop() {
  SLOG(this, 3) << "In " << __func__;
  attempt_count_ = 0;
  CleanupTrial();
}

void PortalDetector::HttpRequestSuccessCallback(
    std::shared_ptr<brillo::http::Response> response) {
  // TODO(matthewmwang): check for 0 length data as well
  int status_code = response->GetStatusCode();
  result_->http_probe_completed = true;
  result_->http_phase = Phase::kContent;
  result_->http_status_code = status_code;
  if (status_code == brillo::http::status_code::NoContent) {
    result_->http_status = Status::kSuccess;
  } else if (status_code == brillo::http::status_code::Redirect ||
             status_code == brillo::http::status_code::RedirectKeepVerb) {
    result_->http_status = Status::kRedirect;
    std::string redirect_url_string =
        response->GetHeader(brillo::http::response_header::kLocation);
    if (!redirect_url_string.empty()) {
      HttpUrl redirect_url;
      if (!redirect_url.ParseFromString(redirect_url_string)) {
        result_->http_status = Status::kFailure;
      } else {
        result_->redirect_url_string = redirect_url_string;
        result_->probe_url_string = http_url_string_;
      }
    }
    LOG(INFO) << LoggingTag()
              << ": Redirect response, Redirect URL: " << redirect_url_string
              << ", response status code: " << status_code;
  } else {
    result_->http_status = Status::kFailure;
  }
  LOG(INFO) << LoggingTag()
            << ": HTTP probe response status code=" << status_code
            << " status=" << result_->http_status;
  if (result_->IsComplete())
    CompleteTrial(*result_);
}

void PortalDetector::HttpsRequestSuccessCallback(
    std::shared_ptr<brillo::http::Response> response) {
  int status_code = response->GetStatusCode();
  // The HTTPS probe is successful and indicates no portal was present only if
  // it gets the expected 204 status code. Any other result is a failure.
  result_->https_probe_completed = true;
  result_->https_phase = Phase::kContent;
  result_->https_status = (status_code == brillo::http::status_code::NoContent)
                              ? Status::kSuccess
                              : Status::kFailure;
  LOG(INFO) << LoggingTag()
            << ": HTTPS probe response status code=" << status_code
            << " status=" << result_->https_status;
  if (result_->IsComplete())
    CompleteTrial(*result_);
}

void PortalDetector::HttpRequestErrorCallback(HttpRequest::Result http_result) {
  result_->http_probe_completed = true;
  result_->http_phase = GetPortalPhaseForRequestResult(http_result);
  result_->http_status = GetPortalStatusForRequestResult(http_result);
  LOG(INFO) << LoggingTag()
            << ": HTTP probe failed with phase=" << result_->http_phase
            << " status=" << result_->http_status;
  if (result_->IsComplete())
    CompleteTrial(*result_);
}

void PortalDetector::HttpsRequestErrorCallback(
    HttpRequest::Result https_result) {
  result_->https_probe_completed = true;
  result_->https_phase = GetPortalPhaseForRequestResult(https_result);
  result_->https_status = GetPortalStatusForRequestResult(https_result);
  LOG(INFO) << LoggingTag()
            << ": HTTPS probe failed with phase=" << result_->https_phase
            << " status=" << result_->https_status;
  if (result_->IsComplete())
    CompleteTrial(*result_);
}

bool PortalDetector::IsInProgress() {
  return is_active_;
}

base::TimeDelta PortalDetector::GetNextAttemptDelay() const {
  if (attempt_count_ == 0)
    return base::TimeDelta();

  base::TimeDelta next_interval =
      kPortalCheckInterval * (1 << (attempt_count_ - 1));
  if (next_interval > kMaxPortalCheckInterval)
    next_interval = kMaxPortalCheckInterval;

  const auto next_attempt = last_attempt_start_time_ + next_interval;
  const auto now = base::Time::NowFromSystemTime();
  auto next_delay = next_attempt - now;
  if (next_delay < kMinPortalCheckDelay)
    next_delay = kMinPortalCheckDelay;

  return next_delay;
}

// static
const std::string PortalDetector::PhaseToString(Phase phase) {
  switch (phase) {
    case Phase::kConnection:
      return kPortalDetectionPhaseConnection;
    case Phase::kDNS:
      return kPortalDetectionPhaseDns;
    case Phase::kHTTP:
      return kPortalDetectionPhaseHttp;
    case Phase::kContent:
      return kPortalDetectionPhaseContent;
    case Phase::kUnknown:
    default:
      return kPortalDetectionPhaseUnknown;
  }
}

// static
const std::string PortalDetector::StatusToString(Status status) {
  switch (status) {
    case Status::kSuccess:
      return kPortalDetectionStatusSuccess;
    case Status::kTimeout:
      return kPortalDetectionStatusTimeout;
    case Status::kRedirect:
      return kPortalDetectionStatusRedirect;
    case Status::kFailure:
    default:
      return kPortalDetectionStatusFailure;
  }
}

// static
const std::string PortalDetector::ValidationStateToString(
    ValidationState state) {
  switch (state) {
    case ValidationState::kInternetConnectivity:
      return "internet-connectivity";
    case ValidationState::kNoConnectivity:
      return "no-connectivity";
    case ValidationState::kPartialConnectivity:
      return "partial-connectivity";
    case ValidationState::kPortalRedirect:
      return "portal-redirect";
  }
}

// static
PortalDetector::Phase PortalDetector::GetPortalPhaseForRequestResult(
    HttpRequest::Result result) {
  switch (result) {
    case HttpRequest::kResultSuccess:
      return Phase::kContent;
    case HttpRequest::kResultDNSFailure:
      return Phase::kDNS;
    case HttpRequest::kResultDNSTimeout:
      return Phase::kDNS;
    case HttpRequest::kResultConnectionFailure:
      return Phase::kConnection;
    case HttpRequest::kResultHTTPFailure:
      return Phase::kHTTP;
    case HttpRequest::kResultHTTPTimeout:
      return Phase::kHTTP;
    case HttpRequest::kResultInvalidInput:
    case HttpRequest::kResultUnknown:
    default:
      return Phase::kUnknown;
  }
}

// static
PortalDetector::Status PortalDetector::GetPortalStatusForRequestResult(
    HttpRequest::Result result) {
  switch (result) {
    case HttpRequest::kResultSuccess:
      // The request completed without receiving the expected payload.
      return Status::kFailure;
    case HttpRequest::kResultDNSFailure:
      return Status::kFailure;
    case HttpRequest::kResultDNSTimeout:
      return Status::kTimeout;
    case HttpRequest::kResultConnectionFailure:
      return Status::kFailure;
    case HttpRequest::kResultHTTPFailure:
      return Status::kFailure;
    case HttpRequest::kResultHTTPTimeout:
      return Status::kTimeout;
    case HttpRequest::kResultInvalidInput:
    case HttpRequest::kResultUnknown:
    default:
      return Status::kFailure;
  }
}

PortalDetector::ValidationState PortalDetector::Result::GetValidationState()
    const {
  if (http_phase != PortalDetector::Phase::kContent) {
    return ValidationState::kNoConnectivity;
  }
  if (http_status == PortalDetector::Status::kSuccess &&
      https_status == PortalDetector::Status::kSuccess) {
    return ValidationState::kInternetConnectivity;
  }
  if (http_status == PortalDetector::Status::kRedirect) {
    return redirect_url_string.empty() ? ValidationState::kPartialConnectivity
                                       : ValidationState::kPortalRedirect;
  }
  if (http_status == PortalDetector::Status::kTimeout &&
      https_status != PortalDetector::Status::kSuccess) {
    return ValidationState::kNoConnectivity;
  }
  return ValidationState::kPartialConnectivity;
}

std::string PortalDetector::LoggingTag() const {
  return logging_tag_ + " attempt=" + std::to_string(attempt_count_);
}

bool PortalDetector::Result::IsComplete() const {
  return http_probe_completed && https_probe_completed;
}

std::ostream& operator<<(std::ostream& stream, PortalDetector::Phase phase) {
  return stream << PortalDetector::PhaseToString(phase);
}

std::ostream& operator<<(std::ostream& stream, PortalDetector::Status status) {
  return stream << PortalDetector::StatusToString(status);
}

std::ostream& operator<<(std::ostream& stream,
                         PortalDetector::ValidationState state) {
  return stream << PortalDetector::ValidationStateToString(state);
}

}  // namespace shill
