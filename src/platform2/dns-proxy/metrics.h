// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DNS_PROXY_METRICS_H_
#define DNS_PROXY_METRICS_H_

#include <sys/socket.h>

#include <utility>
#include <vector>

#include <metrics/metrics_library.h>
#include <metrics/timer.h>

namespace dns_proxy {

class Metrics {
 public:
  // This is not an UMA enum type.
  enum class ProcessType {
    kController,
    kProxySystem,
    kProxyDefault,
    kProxyARC,
  };

  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class ProcessEvent {
    kProxyLaunchSuccess = 0,
    kProxyLaunchFailure = 1,
    kProxyKillFailure = 2,
    kProxyKilled = 3,
    kProxyStopped = 4,
    kProxyContinued = 5,
    kProxyMissing = 6,
    kCapNetBindServiceError = 7,
    kPatchpanelNotInitialized = 8,
    kPatchpanelNotReady = 9,
    kPatchpanelReset = 10,
    kPatchpanelShutdown = 11,
    kPatchpanelNoNamespace = 12,
    kPatchpanelNoRedirect = 13,
    kShillNotReady = 14,
    kShillReset = 15,
    kShillShutdown = 16,
    kShillSetProxyAddressRetryExceeded = 17,
    kChromeFeaturesNotInitialized = 18,
    kResolverListenUDPFailure = 19,
    kResolverListenTCPFailure = 20,

    kMaxValue = kResolverListenTCPFailure,
  };

  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class NameserverType {
    kNone = 0,
    kIPv4 = 1,
    kIPv6 = 2,
    kBoth = 3,

    kMaxValue = kBoth,
  };

  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class DnsOverHttpsMode {
    kUnknown = 0,
    kOff = 1,
    kAutomatic = 2,
    kAlwaysOn = 3,

    kMaxValue = kAlwaysOn,
  };

  // This is not an UMA enum type.
  enum class QueryType {
    kPlainText = 0,
    kDnsOverHttps = 1,
  };

  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class QueryResult {
    kFailure = 0,
    kSuccess = 1,

    kMaxValue = kSuccess,
  };

  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class QueryError {
    kNone = 0,
    kDomainNotFound = 1,
    kNoData = 2,
    kBadQuery = 3,
    kQueryRefused = 4,
    kQueryTimeout = 5,
    kQueryCanceled = 6,
    kConnectionRefused = 7,
    kConnectionFailed = 8,
    kUnsupportedProtocol = 9,
    kNotImplemented = 10,
    kInvalidURL = 11,
    kBadHost = 12,
    kTooManyRedirects = 13,
    kSendError = 14,
    kReceiveError = 15,
    kOtherClientError = 16,
    kOtherServerError = 17,
    kEmptyNameServers = 18,
    kEmptyDoHProviders = 19,
    kClientInitializationError = 20,

    kMaxValue = kClientInitializationError,
  };

  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class HttpError {
    kNone = 0,
    kAnyRedirect = 1,
    kBadRequest = 2,
    kPayloadTooLarge = 3,
    kURITooLong = 4,
    kUnsupportedMediaType = 5,
    kTooManyRequests = 6,
    kOtherClientError = 7,
    kNotImplemented = 8,
    kBadGateway = 9,
    kOtherServerError = 10,

    kMaxValue = kOtherServerError,
  };

  // Helper class for measuring time elapsed during different stages of the
  // name resolution process. Accumulates stage timings for later use so that
  // logging metrics do not impact the time spans with i/o overhead.
  class QueryTimer {
   public:
    QueryTimer() = default;
    QueryTimer(const QueryTimer&) = delete;
    QueryTimer& operator=(const QueryTimer&) = delete;
    ~QueryTimer();

    // Measure time elapsed reading query from client.
    // This should be called first to begin the internal timer.
    void StartReceive();
    void StopReceive(bool success);

    // Measure time elapsed spanning the entire resolution step,
    // which may include multiple client calls or retries.
    void StartResolve(bool is_doh = false);
    void StopResolve(bool success);

    // Measure time elapsed sending the reply to the client.
    void StartReply();
    void StopReply(bool success);

    // Records all available metrics.
    void Record(Metrics* metrics);

    void set_metrics(Metrics* metrics);

   private:
    struct resolv_t_ {
      bool success;
      Metrics::QueryType type;
      base::TimeDelta elapsed;
    };

    void Stop();

    Metrics* metrics_{nullptr};
    chromeos_metrics::Timer timer_;
    std::pair<bool, base::TimeDelta> elapsed_recv_;
    std::vector<resolv_t_> elapsed_resolve_;
    std::pair<bool, base::TimeDelta> elapsed_reply_;
    base::TimeDelta elapsed_total_;
  };

  Metrics() = default;
  Metrics(const Metrics&) = delete;
  ~Metrics() = default;
  Metrics& operator=(const Metrics&) = delete;

  void RecordProcessEvent(ProcessType type, ProcessEvent event);
  void RecordNameservers(unsigned int num_ipv4, unsigned int num_ipv6);
  void RecordDnsOverHttpsMode(DnsOverHttpsMode mode);
  void RecordQueryResult(QueryType type, QueryError error, int http_code = -1);
  void RecordQueryResultWithRetries(QueryType type, bool success);
  void RecordQueryDuration(const char* stage, int64_t ms, bool success = true);
  void RecordQueryResolveDuration(QueryType type,
                                  int64_t ms,
                                  bool success = true);
  void RecordProbeResult(sa_family_t family,
                         int num_attempts,
                         QueryError error);

 private:
  MetricsLibrary metrics_;
};

}  // namespace dns_proxy

#endif  // DNS_PROXY_METRICS_H_
