// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dns-proxy/resolver.h"

#include <sys/socket.h>

#include <algorithm>
#include <cmath>
#include <iterator>
#include <optional>
#include <set>
#include <utility>

#include <base/containers/contains.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/rand_util.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_runner.h>
#include <chromeos/patchpanel/dns/dns_protocol.h>
#include <chromeos/patchpanel/dns/dns_query.h>
#include <chromeos/patchpanel/dns/io_buffer.h>
#include <chromeos/patchpanel/net_util.h>

// Using directive is necessary to have the overloaded function for socket data
// structure available.
using patchpanel::operator<<;

namespace dns_proxy {
namespace {
constexpr uint32_t kMaxClientTcpConn = 16;
// Given multiple DNS and DoH servers, Resolver will query each servers
// concurrently. |kMaxConcurrentQueries| sets the maximum number of servers to
// query concurrently.
constexpr int kMaxConcurrentQueries = 3;
// Retry delays are reduced by at most |kRetryDelayJitterMultiplier| times to
// avoid coordinated spikes. Having the value >= 1 might introduce an undefined
// behavior.
constexpr float kRetryJitterMultiplier = 0.2;

constexpr base::TimeDelta kProbeInitialDelay = base::Seconds(1);
constexpr base::TimeDelta kProbeMaximumDelay = base::Hours(1);
constexpr float kProbeRetryMultiplier = 1.5;

// DNS query for resolving "www.gstatic.com" in wire-format data used for
// probing. Transaction ID for the query is empty. This is safe because we
// don't care about the resolving result of the query.
constexpr char kDNSQueryGstatic[] =
    "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x03\x77\x77\x77"
    "\x07\x67\x73\x74\x61\x74\x69\x63\x03\x63\x6f\x6d\x00\x00\x01\x00"
    "\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00";

// Get the time to wait until the next probe.
static base::TimeDelta GetTimeUntilProbe(int num_attempts) {
  base::TimeDelta delay = kProbeInitialDelay;
  delay *= pow(kProbeRetryMultiplier, num_attempts);
  delay -= base::RandDouble() * kRetryJitterMultiplier * delay;
  return std::min(delay, kProbeMaximumDelay);
}

Metrics::QueryError AresStatusMetric(int status) {
  switch (status) {
    case ARES_SUCCESS:
      return Metrics::QueryError::kNone;
    case ARES_ENODATA:
      return Metrics::QueryError::kNoData;
    case ARES_ENOTFOUND:
      return Metrics::QueryError::kDomainNotFound;
    case ARES_ENOTIMP:
      return Metrics::QueryError::kNotImplemented;
    case ARES_EREFUSED:
      return Metrics::QueryError::kQueryRefused;
    case ARES_EFORMERR:
    case ARES_EBADQUERY:
    case ARES_EBADNAME:
    case ARES_EBADFAMILY:
      return Metrics::QueryError::kBadQuery;
    case ARES_ESERVFAIL:
    case ARES_EBADRESP:
      return Metrics::QueryError::kOtherServerError;
    case ARES_ECONNREFUSED:
      return Metrics::QueryError::kConnectionRefused;
    case ARES_ETIMEOUT:
      return Metrics::QueryError::kQueryTimeout;
    default:
      return Metrics::QueryError::kOtherClientError;
  }
}

Metrics::QueryError CurlCodeMetric(int code) {
  switch (code) {
    case CURLE_OK:
      return Metrics::QueryError::kNone;
    case CURLE_UNSUPPORTED_PROTOCOL:
      return Metrics::QueryError::kUnsupportedProtocol;
    case CURLE_URL_MALFORMAT:
    case CURLE_BAD_CONTENT_ENCODING:
      return Metrics::QueryError::kBadQuery;
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_RESOLVE_PROXY:
      return Metrics::QueryError::kBadHost;
    case CURLE_COULDNT_CONNECT:
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_PEER_FAILED_VERIFICATION:
      return Metrics::QueryError::kConnectionFailed;
    case CURLE_REMOTE_ACCESS_DENIED:
    case CURLE_SSL_CLIENTCERT:
      return Metrics::QueryError::kConnectionRefused;
    case CURLE_OPERATION_TIMEDOUT:
      return Metrics::QueryError::kQueryTimeout;
    case CURLE_TOO_MANY_REDIRECTS:
      return Metrics::QueryError::kTooManyRedirects;
    case CURLE_GOT_NOTHING:
      return Metrics::QueryError::kNoData;
    case CURLE_SEND_ERROR:
    case CURLE_WRITE_ERROR:
    case CURLE_AGAIN:
      return Metrics::QueryError::kSendError;
    case CURLE_RECV_ERROR:
    case CURLE_READ_ERROR:
      return Metrics::QueryError::kReceiveError;
    case CURLE_WEIRD_SERVER_REPLY:
    case CURLE_RANGE_ERROR:
      return Metrics::QueryError::kOtherServerError;
    default:
      return Metrics::QueryError::kOtherClientError;
  }
}

// Return the next ID for SocketFds.
int NextId() {
  static int next_id = 1;
  return next_id++;
}

}  // namespace

std::ostream& operator<<(std::ostream& stream, const Resolver& resolver) {
  resolver.logger_.Run(stream);
  return stream;
}

Resolver::SocketFd::SocketFd(int type, int fd)
    : type(type), fd(fd), num_retries(0), num_active_queries(0), id(NextId()) {
  if (type == SOCK_STREAM) {
    socklen = 0;
    return;
  }
  socklen = sizeof(src);
}

Resolver::TCPConnection::TCPConnection(
    std::unique_ptr<patchpanel::Socket> sock,
    const base::RepeatingCallback<void(int, int)>& callback)
    : sock(std::move(sock)) {
  watcher = base::FileDescriptorWatcher::WatchReadable(
      TCPConnection::sock->fd(),
      base::BindRepeating(callback, TCPConnection::sock->fd(), SOCK_STREAM));
}

Resolver::ProbeState::ProbeState(const std::string& target,
                                 bool doh,
                                 bool validated)
    : target(target), doh(doh), validated(validated), num_retries(0) {}

Resolver::Resolver(base::RepeatingCallback<void(std::ostream& stream)> logger,
                   base::TimeDelta timeout,
                   base::TimeDelta retry_delay,
                   int max_num_retries)
    : logger_(logger),
      always_on_doh_(false),
      doh_enabled_(false),
      retry_delay_(retry_delay),
      max_num_retries_(max_num_retries),
      metrics_(new Metrics) {
  ares_client_ = std::make_unique<AresClient>(timeout);
  curl_client_ = std::make_unique<DoHCurlClient>(timeout);
}

Resolver::Resolver(std::unique_ptr<AresClient> ares_client,
                   std::unique_ptr<DoHCurlClientInterface> curl_client,
                   bool disable_probe,
                   std::unique_ptr<Metrics> metrics)
    : logger_(base::DoNothing()),
      always_on_doh_(false),
      doh_enabled_(false),
      disable_probe_(disable_probe),
      metrics_(std::move(metrics)),
      ares_client_(std::move(ares_client)),
      curl_client_(std::move(curl_client)) {}

bool Resolver::ListenTCP(struct sockaddr* addr) {
  auto tcp_src = std::make_unique<patchpanel::Socket>(
      addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK);
  if (!tcp_src->is_valid()) {
    PLOG(ERROR) << *this << " Failed to create TCP socket";
    return false;
  }

  socklen_t len =
      addr->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
  if (!tcp_src->Bind(addr, len)) {
    PLOG(ERROR) << *this << " Cannot bind TCP listening socket to " << *addr;
    return false;
  }

  if (!tcp_src->Listen(kMaxClientTcpConn)) {
    PLOG(ERROR) << *this << " Cannot listen on " << *addr;
    return false;
  }

  // Run the accept loop.
  LOG(INFO) << *this << " Accepting TCP connections on " << *addr;
  tcp_src_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      tcp_src->fd(), base::BindRepeating(&Resolver::OnTCPConnection,
                                         weak_factory_.GetWeakPtr()));
  tcp_src_ = std::move(tcp_src);

  return true;
}

bool Resolver::ListenUDP(struct sockaddr* addr) {
  auto udp_src = std::make_unique<patchpanel::Socket>(
      addr->sa_family, SOCK_DGRAM | SOCK_NONBLOCK);
  if (!udp_src->is_valid()) {
    PLOG(ERROR) << *this << " Failed to create UDP socket";
    return false;
  }

  socklen_t len =
      addr->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
  if (!udp_src->Bind(addr, len)) {
    PLOG(ERROR) << *this << " Cannot bind UDP socket to " << *addr;
    return false;
  }

  // Start listening.
  LOG(INFO) << *this << " Accepting UDP queries on " << *addr;
  udp_src_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      udp_src->fd(),
      base::BindRepeating(&Resolver::OnDNSQuery, weak_factory_.GetWeakPtr(),
                          udp_src->fd(), SOCK_DGRAM));
  udp_src_ = std::move(udp_src);
  return true;
}

void Resolver::OnTCPConnection() {
  struct sockaddr_storage client_src = {};
  socklen_t sockaddr_len = sizeof(client_src);
  auto client_conn =
      tcp_src_->Accept((struct sockaddr*)&client_src, &sockaddr_len);
  if (!client_conn) {
    PLOG(ERROR) << *this << " Failed to accept TCP connection";
    return;
  }
  tcp_connections_.emplace(
      client_conn->fd(),
      new TCPConnection(std::move(client_conn),
                        base::BindRepeating(&Resolver::OnDNSQuery,
                                            weak_factory_.GetWeakPtr())));
}

void Resolver::HandleAresResult(base::WeakPtr<SocketFd> sock_fd,
                                base::WeakPtr<ProbeState> probe_state,
                                int status,
                                unsigned char* msg,
                                size_t len) {
  // Query is already handled.
  if (!sock_fd) {
    return;
  }

  // Query failed, restart probing.
  // Errors that may be caused by its query's data are not considered as
  // failures:
  // - ARES_FORMERR means that the query data is incorrect.
  // - ARES_ENODATA means that the domain has no answers.
  // - ARES_ENOTIMP means that the operation requested is not implemented.
  // We don't treat this as an error as the user can create these packets
  // manually.
  static const std::set<int> query_success_statuses = {
      ARES_SUCCESS, ARES_EFORMERR, ARES_ENODATA, ARES_ENOTIMP};
  if (probe_state && probe_state->validated &&
      !base::Contains(query_success_statuses, status)) {
    auto target = probe_state->target;
    // |probe_state| will be invalidated by RestartProbe.
    RestartProbe(probe_state);
    int attempt = sock_fd->num_retries + 1;
    LOG(ERROR) << *this << " Do53 query to " << target << " failed after "
               << attempt << " attempt: " << ares_strerror(status) << ". "
               << validated_name_servers_.size() << "/" << name_servers_.size()
               << " validated name servers";
  }

  sock_fd->num_active_queries--;
  // Don't process failing result that is not the last result.
  if (status != ARES_SUCCESS && sock_fd->num_active_queries > 0)
    return;

  sock_fd->timer.StopResolve(status == ARES_SUCCESS);
  if (metrics_)
    metrics_->RecordQueryResult(Metrics::QueryType::kPlainText,
                                AresStatusMetric(status));

  if (status == ARES_SUCCESS) {
    ReplyDNS(sock_fd, msg, len);
    sock_fds_.erase(sock_fd->id);
    return;
  }

  // Process the last unsuccessful result.
  // Retry query upon failure.
  if (sock_fd->num_retries++ >= max_num_retries_) {
    LOG(ERROR) << *this
               << " Failed to do ares lookup: " << ares_strerror(status);
    sock_fds_.erase(sock_fd->id);
    return;
  }

  // Retry resolving the domain.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&Resolver::Resolve, weak_factory_.GetWeakPtr(),
                                sock_fd, false /* fallback */));
}

void Resolver::HandleCurlResult(base::WeakPtr<SocketFd> sock_fd,
                                base::WeakPtr<ProbeState> probe_state,
                                const DoHCurlClient::CurlResult& res,
                                unsigned char* msg,
                                size_t len) {
  // Query is already handled.
  if (!sock_fd) {
    return;
  }

  // Query failed, restart probing.
  if (probe_state && probe_state->validated && res.http_code != kHTTPOk) {
    auto target = probe_state->target;
    // |probe_state| will be invalidated by RestartProbe.
    RestartProbe(probe_state);
    int attempt = sock_fd->num_retries + 1;
    LOG(WARNING) << *this << " DoH query to " << target << " failed after "
                 << attempt << " attempt, http status code: " << res.http_code
                 << ". " << validated_doh_providers_.size() << "/"
                 << doh_providers_.size() << " validated DoH providers";
  }

  sock_fd->num_active_queries--;
  // Don't process failing result that is not the last result.
  if (res.http_code != kHTTPOk && sock_fd->num_active_queries > 0)
    return;

  sock_fd->timer.StopResolve(res.curl_code == CURLE_OK);
  if (metrics_)
    metrics_->RecordQueryResult(Metrics::QueryType::kDnsOverHttps,
                                CurlCodeMetric(res.curl_code), res.http_code);

  // Process result.
  if (res.curl_code != CURLE_OK) {
    LOG(ERROR) << *this << " DoH resolution failed: "
               << curl_easy_strerror(res.curl_code);
    if (always_on_doh_) {
      // TODO(jasongustaman): Send failure reply with RCODE.
      sock_fds_.erase(sock_fd->id);
      return;
    }
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&Resolver::Resolve, weak_factory_.GetWeakPtr(), sock_fd,
                       true /* fallback */));
    return;
  }

  switch (res.http_code) {
    case kHTTPOk: {
      ReplyDNS(sock_fd, msg, len);
      sock_fds_.erase(sock_fd->id);
      return;
    }
    case kHTTPTooManyRequests: {
      if (sock_fd->num_retries >= max_num_retries_) {
        LOG(ERROR) << *this << " Failed to resolve hostname, retried "
                   << max_num_retries_ << " tries";
        sock_fds_.erase(sock_fd->id);
        return;
      }

      // Add jitter to avoid coordinated spikes of retries.
      base::TimeDelta retry_delay_jitter =
          (1 - (base::RandDouble() * kRetryJitterMultiplier)) * retry_delay_;

      // Retry resolving the domain.
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
          FROM_HERE,
          base::BindOnce(&Resolver::Resolve, weak_factory_.GetWeakPtr(),
                         sock_fd, false /* fallback */),
          retry_delay_jitter);
      sock_fd->num_retries++;
      return;
    }
    default: {
      LOG(ERROR) << *this << " Failed to do curl lookup, HTTP status code: "
                 << res.http_code;
      if (always_on_doh_) {
        // TODO(jasongustaman): Send failure reply with RCODE.
        sock_fds_.erase(sock_fd->id);
        return;
      }
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE,
          base::BindOnce(&Resolver::Resolve, weak_factory_.GetWeakPtr(),
                         sock_fd, true /* fallback */));
    }
  }
}

void Resolver::HandleDoHProbeResult(base::WeakPtr<ProbeState> probe_state,
                                    const ProbeData& probe_data,
                                    const DoHCurlClient::CurlResult& res,
                                    unsigned char* msg,
                                    size_t len) {
  if (!probe_state) {
    return;
  }

  int attempt = probe_data.num_retries + 1;
  auto now = base::Time::Now();
  auto attempt_latency = now - probe_data.start_time;

  if (res.curl_code != CURLE_OK) {
    LOG(INFO) << *this << " DoH probe attempt " << attempt << " to "
              << probe_state->target
              << " failed: " << curl_easy_strerror(res.curl_code) << " ("
              << attempt_latency << ")";
    return;
  }
  if (res.http_code != kHTTPOk) {
    LOG(INFO) << *this << " DoH probe attempt " << attempt << " to "
              << probe_state->target
              << " failed, HTTP status code: " << res.http_code << " ("
              << attempt_latency << ")";
    return;
  }

  validated_doh_providers_.push_back(probe_state->target);

  LOG(INFO) << *this << " DoH probe attempt " << attempt << " to "
            << probe_state->target << " succeeded (" << attempt_latency << "). "
            << validated_doh_providers_.size() << "/" << doh_providers_.size()
            << " validated DoH providers";

  // Clear the old probe state to stop running probes.
  // Entry must be valid as |probe_state| is still valid.
  const auto& doh_provider = doh_providers_.find(probe_state->target);
  doh_provider->second = std::make_unique<ProbeState>(
      doh_provider->first, probe_state->doh, /*validated=*/true);
}

void Resolver::HandleDo53ProbeResult(base::WeakPtr<ProbeState> probe_state,
                                     const ProbeData& probe_data,
                                     int status,
                                     unsigned char* msg,
                                     size_t len) {
  if (metrics_) {
    metrics_->RecordProbeResult(probe_data.family, probe_data.num_retries,
                                AresStatusMetric(status));
  }
  if (!probe_state) {
    return;
  }

  int attempt = probe_data.num_retries + 1;
  auto now = base::Time::Now();
  auto attempt_latency = now - probe_data.start_time;

  if (status != ARES_SUCCESS) {
    LOG(INFO) << *this << " Do53 probe attempt " << attempt << " to "
              << probe_state->target << " failed: " << ares_strerror(status)
              << " (" << attempt_latency << ")";
    return;
  }

  validated_name_servers_.push_back(probe_state->target);

  LOG(INFO) << *this << " Do53 probe attempt " << attempt << " to "
            << probe_state->target << " succeeded (" << attempt_latency << "). "
            << validated_name_servers_.size() << "/" << name_servers_.size()
            << " validated name servers";

  // Clear the old probe state to stop running probes.
  // Entry must be valid as |probe_state| is still valid.
  const auto& name_server = name_servers_.find(probe_state->target);
  name_server->second = std::make_unique<ProbeState>(
      name_server->first, name_server->second->doh, /*validated=*/true);
}

void Resolver::ReplyDNS(base::WeakPtr<SocketFd> sock_fd,
                        unsigned char* msg,
                        size_t len) {
  sock_fd->timer.StartReply();
  // For TCP, DNS messages have an additional 2-bytes header representing
  // the length of the query. Add the additional header for the reply.
  uint16_t dns_len = htons(len);
  struct iovec iov_out[2];
  iov_out[0].iov_base = &dns_len;
  iov_out[0].iov_len = 2;
  // For UDP, skip the additional header. By setting |iov_len| to 0, the
  // additional header |dns_len| will not be sent.
  if (sock_fd->type == SOCK_DGRAM) {
    iov_out[0].iov_len = 0;
  }
  iov_out[1].iov_base = static_cast<void*>(msg);
  iov_out[1].iov_len = len;
  struct msghdr hdr = {
      .msg_name = nullptr,
      .msg_namelen = 0,
      .msg_iov = iov_out,
      .msg_iovlen = 2,
      .msg_control = nullptr,
      .msg_controllen = 0,
  };
  if (sock_fd->type == SOCK_DGRAM) {
    hdr.msg_name = &sock_fd->src;
    hdr.msg_namelen = sock_fd->socklen;
  }
  const bool ok = sendmsg(sock_fd->fd, &hdr, 0) >= 0;
  sock_fd->timer.StopReply(ok);
  if (!ok) {
    PLOG(ERROR) << *this << " sendmsg() " << sock_fd->fd << " failed";
  }
}

void Resolver::SetNameServers(const std::vector<std::string>& name_servers) {
  SetServers(name_servers, /*doh=*/false);
}

void Resolver::SetDoHProviders(const std::vector<std::string>& doh_providers,
                               bool always_on_doh) {
  always_on_doh_ = always_on_doh;
  doh_enabled_ = !doh_providers.empty();

  SetServers(doh_providers, /*doh=*/true);
}

void Resolver::SetServers(const std::vector<std::string>& new_servers,
                          bool doh) {
  auto& servers = doh ? doh_providers_ : name_servers_;
  auto& validated_servers =
      doh ? validated_doh_providers_ : validated_name_servers_;
  const std::set<std::string> new_servers_set(new_servers.begin(),
                                              new_servers.end());
  bool servers_equal = true;

  // Remove any removed servers.
  for (auto it = servers.begin(); it != servers.end();) {
    if (base::Contains(new_servers_set, it->first)) {
      ++it;
      continue;
    }
    it = servers.erase(it);
    servers_equal = false;
  }

  // Remove any removed servers from validated servers.
  for (auto it = validated_servers.begin(); it != validated_servers.end();) {
    if (base::Contains(new_servers_set, *it)) {
      ++it;
      continue;
    }
    it = validated_servers.erase(it);
  }

  // Probe the new servers.
  for (const auto& new_server : new_servers_set) {
    if (base::Contains(servers, new_server)) {
      continue;
    }
    const auto& probe_state =
        servers
            .emplace(new_server, std::make_unique<ProbeState>(new_server, doh))
            .first;
    Probe(probe_state->second->weak_factory.GetWeakPtr());
    servers_equal = false;
  }

  if (servers_equal)
    return;

  if (doh) {
    LOG(INFO) << *this << " DoH providers are updated, "
              << validated_doh_providers_.size() << "/" << doh_providers_.size()
              << " validated DoH providers";
  } else {
    LOG(INFO) << *this << " Name servers are updated, "
              << validated_name_servers_.size() << "/" << name_servers_.size()
              << " validated name servers";
  }
}

void Resolver::OnDNSQuery(int fd, int type) {
  // Initialize SocketFd to carry necessary data.
  auto sock_fd = std::make_unique<SocketFd>(type, fd);
  // Metrics will be recorded automatically when this object is deleted.
  sock_fd->timer.set_metrics(metrics_.get());

  size_t buf_size;
  struct sockaddr* src;
  switch (type) {
    case SOCK_DGRAM:
      sock_fd->msg = sock_fd->buf;
      buf_size = kDNSBufSize;
      src = reinterpret_cast<struct sockaddr*>(&sock_fd->src);
      break;
    case SOCK_STREAM:
      // For TCP, DNS has an additional 2-bytes header representing the length
      // of the query. Move the receiving buffer, so it is 4-bytes aligned.
      sock_fd->msg = sock_fd->buf + 2;
      buf_size = kDNSBufSize - 2;
      src = nullptr;
      break;
    default:
      LOG(DFATAL) << *this << " Unexpected socket type: " << type;
      return;
  }
  sock_fd->timer.StartReceive();
  sock_fd->len =
      recvfrom(fd, sock_fd->msg, buf_size, 0, src, &sock_fd->socklen);
  // Assume success - on failure, the correct value will be recorded.
  sock_fd->timer.StopReceive(true);
  if (sock_fd->len < 0) {
    sock_fd->timer.StopReceive(false);
    PLOG(WARNING) << *this << " recvfrom failed";
    return;
  }
  // Handle TCP connection closed.
  if (sock_fd->len == 0) {
    sock_fd->timer.StopReceive(false);
    tcp_connections_.erase(fd);
    return;
  }

  // For TCP, DNS have an additional 2-bytes header representing the length of
  // the query. Trim the additional header to be used by CURL or Ares.
  if (type == SOCK_STREAM && sock_fd->len > 2) {
    sock_fd->msg += 2;
    sock_fd->len -= 2;
  }

  const auto& sock_fd_it =
      sock_fds_.emplace(sock_fd->id, std::move(sock_fd)).first;
  Resolve(sock_fd_it->second->weak_factory.GetWeakPtr());
}

bool Resolver::ResolveDNS(base::WeakPtr<SocketFd> sock_fd, bool doh) {
  if (!sock_fd) {
    LOG(ERROR) << *this
               << " Unexpected ResolveDNS() call with deleted SocketFd";
    return false;
  }

  const auto query_type =
      doh ? Metrics::QueryType::kDnsOverHttps : Metrics::QueryType::kPlainText;
  const auto& name_servers = GetActiveNameServers();
  if (name_servers.empty()) {
    LOG(ERROR) << *this << " Name server list must not be empty";
    if (metrics_) {
      metrics_->RecordQueryResult(query_type,
                                  Metrics::QueryError::kEmptyNameServers);
    }
    return false;
  }

  const auto& doh_providers = GetActiveDoHProviders();
  if (doh && doh_providers.empty()) {
    // No DoH providers are currently validated, fallback to Do53.
    if (!doh_providers_.empty()) {
      return false;
    }
    LOG(ERROR) << *this << " DoH provider list must not be empty";
    if (metrics_) {
      metrics_->RecordQueryResult(Metrics::QueryType::kDnsOverHttps,
                                  Metrics::QueryError::kEmptyDoHProviders);
    }
    return false;
  }

  // Start multiple concurrent queries.
  const auto& targets = doh ? doh_providers : name_servers;
  for (const auto& target : targets) {
    if (doh) {
      if (!curl_client_->Resolve(
              sock_fd->msg, sock_fd->len,
              base::BindRepeating(
                  &Resolver::HandleCurlResult, weak_factory_.GetWeakPtr(),
                  sock_fd, doh_providers_[target]->weak_factory.GetWeakPtr()),
              name_servers, target)) {
        continue;
      }
    } else {
      if (!ares_client_->Resolve(
              reinterpret_cast<const unsigned char*>(sock_fd->msg),
              sock_fd->len,
              base::BindRepeating(
                  &Resolver::HandleAresResult, weak_factory_.GetWeakPtr(),
                  sock_fd, name_servers_[target]->weak_factory.GetWeakPtr()),
              target, sock_fd->type)) {
        continue;
      }
    }
    if (++sock_fd->num_active_queries >= kMaxConcurrentQueries) {
      break;
    }
  }

  if (sock_fd->num_active_queries > 0)
    return true;

  LOG(ERROR) << *this << " No requests successfully started for query";
  if (metrics_) {
    metrics_->RecordQueryResult(
        query_type, Metrics::QueryError::kClientInitializationError);
  }
  return false;
}

std::vector<std::string> Resolver::GetActiveDoHProviders() {
  if (!always_on_doh_ || !validated_doh_providers_.empty())
    return validated_doh_providers_;

  std::vector<std::string> doh_providers;
  for (const auto& doh_provider : doh_providers_) {
    doh_providers.push_back(doh_provider.first);
  }
  return doh_providers;
}

std::vector<std::string> Resolver::GetActiveNameServers() {
  if (!validated_name_servers_.empty())
    return validated_name_servers_;

  std::vector<std::string> name_servers;
  for (const auto& name_server : name_servers_) {
    name_servers.push_back(name_server.first);
  }
  return name_servers;
}

void Resolver::RestartProbe(base::WeakPtr<ProbeState> probe_state) {
  if (!probe_state)
    return;

  auto& targets = probe_state->doh ? doh_providers_ : name_servers_;
  auto& validated_targets =
      probe_state->doh ? validated_doh_providers_ : validated_name_servers_;
  validated_targets.erase(
      std::remove(validated_targets.begin(), validated_targets.end(),
                  probe_state->target),
      validated_targets.end());

  const auto& target = targets.find(probe_state->target);
  target->second =
      std::make_unique<ProbeState>(target->first, probe_state->doh);
  Probe(target->second->weak_factory.GetWeakPtr());
}

void Resolver::Probe(base::WeakPtr<ProbeState> probe_state) {
  if (disable_probe_)
    return;

  if (!probe_state)
    return;

  // Schedule the next probe now as the probe may run for a long time.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Resolver::Probe, weak_factory_.GetWeakPtr(), probe_state),
      GetTimeUntilProbe(probe_state->num_retries));

  // Run the probe.
  const ProbeData probe_data = {patchpanel::GetIpFamily(probe_state->target),
                                probe_state->num_retries, base::Time::Now()};
  if (probe_state->doh) {
    curl_client_->Resolve(kDNSQueryGstatic, sizeof(kDNSQueryGstatic),
                          base::BindRepeating(&Resolver::HandleDoHProbeResult,
                                              weak_factory_.GetWeakPtr(),
                                              probe_state, probe_data),
                          GetActiveNameServers(), probe_state->target);
  } else {
    ares_client_->Resolve(
        reinterpret_cast<const unsigned char*>(kDNSQueryGstatic),
        sizeof(kDNSQueryGstatic),
        base::BindRepeating(&Resolver::HandleDo53ProbeResult,
                            weak_factory_.GetWeakPtr(), probe_state,
                            probe_data),
        probe_state->target);
  }
  probe_state->num_retries++;
}

void Resolver::Resolve(base::WeakPtr<SocketFd> sock_fd, bool fallback) {
  if (!sock_fd) {
    LOG(ERROR) << *this << " Unexpected Resolve() call with deleted SocketFd";
    return;
  }

  if (doh_enabled_ && !fallback) {
    sock_fd->timer.StartResolve(true);
    if (ResolveDNS(sock_fd, /*doh=*/true))
      return;

    sock_fd->timer.StopResolve(false);
  }
  if (!always_on_doh_) {
    sock_fd->timer.StartResolve();
    if (ResolveDNS(sock_fd, /*doh=*/false))
      return;

    sock_fd->timer.StopResolve(false);
  }

  // Construct and send a response indicating that there is a failure.
  patchpanel::DnsResponse response =
      ConstructServFailResponse(sock_fd->msg, sock_fd->len);
  ReplyDNS(sock_fd,
           reinterpret_cast<unsigned char*>(response.io_buffer()->data()),
           response.io_buffer_size());

  // Query is completed, remove SocketFd.
  sock_fds_.erase(sock_fd->id);
}

patchpanel::DnsResponse Resolver::ConstructServFailResponse(const char* msg,
                                                            int len) {
  // Construct a DNS query from the message buffer.
  std::optional<patchpanel::DnsQuery> query;
  if (len > 0 && len <= dns_proxy::kDNSBufSize) {
    scoped_refptr<patchpanel::IOBufferWithSize> query_buf =
        base::MakeRefCounted<patchpanel::IOBufferWithSize>(len);
    memcpy(query_buf->data(), msg, len);
    query = patchpanel::DnsQuery(query_buf);
  }

  // Set the query id as 0 if the query is invalid.
  uint16_t query_id = 0;
  if (query.has_value() && query->Parse(len)) {
    query_id = query->id();
  } else {
    query.reset();
  }

  // Returns RCODE SERVFAIL response corresponding to the query.
  patchpanel::DnsResponse response(query_id, false /* is_authoritative */,
                                   {} /* answers */, {} /* authority_records */,
                                   {} /* additional_records */, query,
                                   patchpanel::dns_protocol::kRcodeSERVFAIL);
  return response;
}

void Resolver::SetProbingEnabled(bool enable_probe) {
  disable_probe_ = !enable_probe;
}
}  // namespace dns_proxy
