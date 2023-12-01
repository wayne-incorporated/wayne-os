// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/connection_diagnostics.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "shill/dns_client.h"
#include "shill/error.h"
#include "shill/event_dispatcher.h"
#include "shill/http_url.h"
#include "shill/icmp_session.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/net/ip_address.h"

namespace {
// These strings are dependent on ConnectionDiagnostics::Type. Any changes to
// this array should be synced with ConnectionDiagnostics::Type.
const char* const kEventNames[] = {"Portal detection", "Ping DNS servers",
                                   "DNS resolution", "Ping (target web server)",
                                   "Ping (gateway)"};
// These strings are dependent on ConnectionDiagnostics::Phase. Any changes to
// this array should be synced with ConnectionDiagnostics::Phase.
const char* const kPhaseNames[] = {"Start", "End", "End (Content)", "End (DNS)",
                                   "End (HTTP/CXN)"};
// These strings are dependent on ConnectionDiagnostics::Result. Any changes to
// this array should be synced with ConnectionDiagnostics::Result.
const char* const kResultNames[] = {"Success", "Failure", "Timeout"};

}  // namespace

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
}  // namespace Logging

const char ConnectionDiagnostics::kIssueIPCollision[] =
    "IP collision detected. Another host on the local network has been "
    "assigned the same IP address.";
const char ConnectionDiagnostics::kIssueRouting[] = "Routing problem detected.";
const char ConnectionDiagnostics::kIssueHTTP[] =
    "Target hostname is pingable. Connectivity problems might be caused by a "
    "firewall, a web proxy, or a captive portal";
const char ConnectionDiagnostics::kIssueDNSServerMisconfig[] =
    "DNS servers responding to DNS queries, but sending invalid responses. "
    "DNS servers might be misconfigured.";
const char ConnectionDiagnostics::kIssueDNSServerNoResponse[] =
    "At least one DNS server is pingable, but is not responding to DNS "
    "requests. DNS server issue detected.";
const char ConnectionDiagnostics::kIssueNoDNSServersConfigured[] =
    "No DNS servers have been configured for this connection -- either the "
    "DHCP server or user configuration is invalid.";
const char ConnectionDiagnostics::kIssueDNSServersInvalid[] =
    "All configured DNS server addresses are invalid.";
const char ConnectionDiagnostics::kIssueNone[] =
    "No connection issue detected.";
const char ConnectionDiagnostics::kIssueGatewayUpstream[] =
    "We can find a route to the target web server at a remote IP address, "
    "and the local gateway is pingable. Gatway issue or upstream "
    "connectivity problem detected.";
const char ConnectionDiagnostics::kIssueGatewayNotResponding[] =
    "This gateway appears to be on the local network, but is not responding to "
    "pings.";
const char ConnectionDiagnostics::kIssueServerNotResponding[] =
    "This web server appears to be on the local network, but is not responding "
    "to pings.";
const char ConnectionDiagnostics::kIssueGatewayArpFailed[] =
    "No ARP entry for the gateway. Either the gateway does not exist on the "
    "local network, or there are link layer issues.";
const char ConnectionDiagnostics::kIssueServerArpFailed[] =
    "No ARP entry for the web server. Either the web server does not exist on "
    "the local network, or there are link layer issues.";
const char ConnectionDiagnostics::kIssueInternalError[] =
    "The connection diagnostics encountered an internal failure.";
const char ConnectionDiagnostics::kIssueGatewayNoNeighborEntry[] =
    "No neighbor table entry for the gateway. Either the gateway does not "
    "exist on the local network, or there are link layer issues.";
const char ConnectionDiagnostics::kIssueServerNoNeighborEntry[] =
    "No neighbor table entry for the web server. Either the web server does "
    "not exist on the local network, or there are link layer issues.";
const char ConnectionDiagnostics::kIssueGatewayNeighborEntryNotConnected[] =
    "Neighbor table entry for the gateway is not in a connected state. Either "
    "the web server does not exist on the local network, or there are link "
    "layer issues.";
const char ConnectionDiagnostics::kIssueServerNeighborEntryNotConnected[] =
    "Neighbor table entry for the web server is not in a connected state. "
    "Either the web server does not exist on the local network, or there are "
    "link layer issues.";
const int ConnectionDiagnostics::kMaxDNSRetries = 2;

ConnectionDiagnostics::ConnectionDiagnostics(
    std::string iface_name,
    int iface_index,
    const IPAddress& ip_address,
    const IPAddress& gateway,
    const std::vector<std::string>& dns_list,
    EventDispatcher* dispatcher,
    Metrics* metrics,
    ResultCallback result_callback)
    : dispatcher_(dispatcher),
      metrics_(metrics),
      iface_name_(iface_name),
      iface_index_(iface_index),
      ip_address_(ip_address),
      gateway_(gateway),
      dns_list_(dns_list),
      icmp_session_(new IcmpSession(dispatcher_)),
      num_dns_attempts_(0),
      running_(false),
      result_callback_(std::move(result_callback)),
      weak_ptr_factory_(this) {
  dns_client_.reset(new DnsClient(
      ip_address.family(), iface_name, DnsClient::kDnsTimeoutMilliseconds,
      dispatcher_,
      base::BindRepeating(&ConnectionDiagnostics::OnDNSResolutionComplete,
                          weak_ptr_factory_.GetWeakPtr())));
  for (size_t i = 0; i < dns_list_.size(); i++) {
    id_to_pending_dns_server_icmp_session_[i] =
        std::make_unique<IcmpSession>(dispatcher_);
  }
}

ConnectionDiagnostics::~ConnectionDiagnostics() {
  Stop();
}

bool ConnectionDiagnostics::Start(const std::string& url_string) {
  LOG(INFO) << iface_name_ << ": Starting diagnostics for " << url_string;

  if (running()) {
    LOG(ERROR) << iface_name_ << ": Diagnostics already started";
    return false;
  }

  target_url_.reset(new HttpUrl());
  if (!target_url_->ParseFromString(url_string)) {
    LOG(ERROR) << iface_name_ << ": Failed to parse URL \"" << url_string
               << "\". Cannot start diagnostics";
    Stop();
    return false;
  }

  running_ = true;
  // Ping DNS servers to make sure at least one is reachable before resolving
  // the hostname of |target_url_|;
  dispatcher_->PostTask(FROM_HERE,
                        base::BindOnce(&ConnectionDiagnostics::PingDNSServers,
                                       weak_ptr_factory_.GetWeakPtr()));
  return true;
}

void ConnectionDiagnostics::Stop() {
  running_ = false;
  num_dns_attempts_ = 0;
  diagnostic_events_.clear();
  dns_client_.reset();
  icmp_session_->Stop();
  id_to_pending_dns_server_icmp_session_.clear();
  target_url_.reset();
}

// static
std::string ConnectionDiagnostics::EventToString(const Event& event) {
  auto message = base::StringPrintf(
      "Event: %-26sPhase: %-17sResult: %-10s", kEventNames[event.type],
      kPhaseNames[event.phase], kResultNames[event.result]);
  if (!event.message.empty()) {
    message.append("Msg: " + event.message);
  }
  return message;
}

void ConnectionDiagnostics::AddEvent(Type type, Phase phase, Result result) {
  AddEventWithMessage(type, phase, result, "");
}

void ConnectionDiagnostics::AddEventWithMessage(Type type,
                                                Phase phase,
                                                Result result,
                                                const std::string& message) {
  diagnostic_events_.push_back(Event(type, phase, result, message));
}

void ConnectionDiagnostics::ReportResultAndStop(const std::string& issue) {
  metrics_->NotifyConnectionDiagnosticsIssue(issue);
  for (size_t i = 0; i < diagnostic_events_.size(); ++i) {
    LOG(INFO) << iface_name_ << ": Diagnostics event #" << i << ": "
              << EventToString(diagnostic_events_[i]);
  }
  LOG(INFO) << iface_name_ << ": Connection diagnostics result: " << issue;
  if (!result_callback_.is_null()) {
    std::move(result_callback_).Run(issue, diagnostic_events_);
  }
  Stop();
}

void ConnectionDiagnostics::ResolveTargetServerIPAddress(
    const std::vector<std::string>& dns_list) {
  Error e;
  if (!dns_client_->Start(dns_list, target_url_->host(), &e)) {
    LOG(ERROR) << iface_name_ << ": could not start DNS on -- " << e.message();
    AddEventWithMessage(kTypeResolveTargetServerIP, kPhaseStart, kResultFailure,
                        e.message());
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  AddEventWithMessage(kTypeResolveTargetServerIP, kPhaseStart, kResultSuccess,
                      base::StringPrintf("Attempt #%d", num_dns_attempts_));
  SLOG(2) << __func__ << ": looking up " << target_url_->host() << " (attempt "
          << num_dns_attempts_ << ")";
  ++num_dns_attempts_;
}

void ConnectionDiagnostics::PingDNSServers() {
  if (dns_list_.empty()) {
    LOG(ERROR) << iface_name_ << ": no DNS servers for network connection on "
               << iface_name_;
    AddEventWithMessage(kTypePingDNSServers, kPhaseStart, kResultFailure,
                        "No DNS servers for this connection");
    ReportResultAndStop(kIssueNoDNSServersConfigured);
    return;
  }

  pingable_dns_servers_.clear();
  size_t num_invalid_dns_server_addr = 0;
  size_t num_failed_icmp_session_start = 0;
  for (size_t i = 0; i < dns_list_.size(); ++i) {
    // If we encounter any errors starting ping for any DNS server, carry on
    // attempting to ping the other DNS servers rather than failing. We only
    // need to successfully ping a single DNS server to decide whether or not
    // DNS servers can be reached.
    const auto dns_server_ip_addr = IPAddress::CreateFromString(dns_list_[i]);
    if (!dns_server_ip_addr.has_value()) {
      LOG(ERROR) << iface_name_
                 << ": could not parse DNS server IP address from string";
      ++num_invalid_dns_server_addr;
      id_to_pending_dns_server_icmp_session_.erase(i);
      continue;
    }

    auto session_iter = id_to_pending_dns_server_icmp_session_.find(i);
    if (session_iter == id_to_pending_dns_server_icmp_session_.end())
      continue;

    if (!session_iter->second->Start(
            *dns_server_ip_addr, iface_index_,
            base::BindOnce(&ConnectionDiagnostics::OnPingDNSServerComplete,
                           weak_ptr_factory_.GetWeakPtr(), i))) {
      LOG(ERROR) << iface_name_ << "Failed to initiate ping for DNS server at "
                 << dns_server_ip_addr->ToString();
      ++num_failed_icmp_session_start;
      id_to_pending_dns_server_icmp_session_.erase(i);
      continue;
    }

    SLOG(2) << __func__ << ": pinging DNS server at "
            << dns_server_ip_addr->ToString();
  }

  if (id_to_pending_dns_server_icmp_session_.empty()) {
    AddEventWithMessage(
        kTypePingDNSServers, kPhaseStart, kResultFailure,
        "Could not start ping for any of the given DNS servers");
    if (num_invalid_dns_server_addr == dns_list_.size()) {
      ReportResultAndStop(kIssueDNSServersInvalid);
    } else if (num_failed_icmp_session_start == dns_list_.size()) {
      ReportResultAndStop(kIssueInternalError);
    }
  } else {
    AddEvent(kTypePingDNSServers, kPhaseStart, kResultSuccess);
  }
}

void ConnectionDiagnostics::PingHost(const IPAddress& address) {
  SLOG(2) << __func__;

  Type event_type =
      address.Equals(gateway_) ? kTypePingGateway : kTypePingTargetServer;
  if (!icmp_session_->Start(
          address, iface_index_,
          base::BindOnce(&ConnectionDiagnostics::OnPingHostComplete,
                         weak_ptr_factory_.GetWeakPtr(), event_type,
                         address))) {
    LOG(ERROR) << iface_name_ << ": failed to start ICMP session with "
               << address.ToString();
    AddEventWithMessage(
        event_type, kPhaseStart, kResultFailure,
        "Failed to start ICMP session with " + address.ToString());
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  AddEventWithMessage(event_type, kPhaseStart, kResultSuccess,
                      "Pinging " + address.ToString());
}

void ConnectionDiagnostics::OnPingDNSServerComplete(
    int dns_server_index, const std::vector<base::TimeDelta>& result) {
  SLOG(2) << __func__ << "(DNS server index " << dns_server_index << ")";

  if (!id_to_pending_dns_server_icmp_session_.erase(dns_server_index)) {
    // This should not happen, since we expect exactly one callback for each
    // IcmpSession started with a unique |dns_server_index| value in
    // ConnectionDiagnostics::PingDNSServers. However, if this does happen for
    // any reason, |id_to_pending_dns_server_icmp_session_| might never become
    // empty, and we might never move to the next step after pinging DNS
    // servers. Stop diagnostics immediately to prevent this from happening.
    LOG(ERROR) << iface_name_
               << ": no matching pending DNS server ICMP session found";
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  if (IcmpSession::AnyRepliesReceived(result)) {
    pingable_dns_servers_.push_back(dns_list_[dns_server_index]);
  }
  if (!id_to_pending_dns_server_icmp_session_.empty()) {
    SLOG(2) << __func__ << ": not yet finished pinging all DNS servers";
    return;
  }

  if (pingable_dns_servers_.empty()) {
    AddEventWithMessage(
        kTypePingDNSServers, kPhaseEnd, kResultFailure,
        "No DNS servers responded to pings. Pinging the gateway at " +
            gateway_.ToString());
    // If no DNS servers can be pinged, try to ping the gateway.
    dispatcher_->PostTask(
        FROM_HERE, base::BindOnce(&ConnectionDiagnostics::PingHost,
                                  weak_ptr_factory_.GetWeakPtr(), gateway_));
    return;
  }

  if (pingable_dns_servers_.size() != dns_list_.size()) {
    AddEventWithMessage(kTypePingDNSServers, kPhaseEnd, kResultSuccess,
                        "Pinged some, but not all, DNS servers successfully");
  } else {
    AddEventWithMessage(kTypePingDNSServers, kPhaseEnd, kResultSuccess,
                        "Pinged all DNS servers successfully");
  }

  if (num_dns_attempts_ < kMaxDNSRetries) {
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&ConnectionDiagnostics::ResolveTargetServerIPAddress,
                       weak_ptr_factory_.GetWeakPtr(), pingable_dns_servers_));
  } else {
    SLOG(2) << __func__ << ": max DNS resolution attempts reached";
    ReportResultAndStop(kIssueDNSServerNoResponse);
  }
}

void ConnectionDiagnostics::OnDNSResolutionComplete(const Error& error,
                                                    const IPAddress& address) {
  SLOG(2) << __func__;

  if (error.IsSuccess()) {
    AddEventWithMessage(kTypeResolveTargetServerIP, kPhaseEnd, kResultSuccess,
                        "Target address is " + address.ToString());
    dispatcher_->PostTask(
        FROM_HERE, base::BindOnce(&ConnectionDiagnostics::PingHost,
                                  weak_ptr_factory_.GetWeakPtr(), address));
  } else if (error.type() == Error::kOperationTimeout) {
    AddEventWithMessage(kTypeResolveTargetServerIP, kPhaseEnd, kResultTimeout,
                        "DNS resolution timed out: " + error.message());
    dispatcher_->PostTask(FROM_HERE,
                          base::BindOnce(&ConnectionDiagnostics::PingDNSServers,
                                         weak_ptr_factory_.GetWeakPtr()));
  } else {
    AddEventWithMessage(kTypeResolveTargetServerIP, kPhaseEnd, kResultFailure,
                        "DNS resolution failed: " + error.message());
    ReportResultAndStop(kIssueDNSServerMisconfig);
  }
}

void ConnectionDiagnostics::OnPingHostComplete(
    Type ping_event_type,
    const IPAddress& address_pinged,
    const std::vector<base::TimeDelta>& result) {
  SLOG(2) << __func__;

  auto message = base::StringPrintf("Destination: %s,  Latencies: ",
                                    address_pinged.ToString().c_str());
  for (const auto& latency : result) {
    if (latency.is_zero()) {
      message.append("NA ");
    } else {
      message.append(base::StringPrintf("%4.2fms ", latency.InMillisecondsF()));
    }
  }

  Result result_type =
      IcmpSession::AnyRepliesReceived(result) ? kResultSuccess : kResultFailure;
  if (IcmpSession::IsPacketLossPercentageGreaterThan(result, 50)) {
    LOG(WARNING) << iface_name_ << ": high packet loss when pinging "
                 << address_pinged.ToString();
  }
  AddEventWithMessage(ping_event_type, kPhaseEnd, result_type, message);
  if (result_type == kResultSuccess) {
    // If pinging the target web server succeeded, we have found a HTTP issue or
    // broken portal. Otherwise, if pinging the gateway succeeded, we have found
    // an upstream connectivity problem or gateway issue.
    ReportResultAndStop(ping_event_type == kTypePingGateway
                            ? kIssueGatewayUpstream
                            : kIssueHTTP);
  } else if (result_type == kResultFailure &&
             ping_event_type == kTypePingTargetServer) {
    // If pinging the target web server fails, try pinging the gateway.
    dispatcher_->PostTask(
        FROM_HERE, base::BindOnce(&ConnectionDiagnostics::PingHost,
                                  weak_ptr_factory_.GetWeakPtr(), gateway_));
  } else if (result_type == kResultFailure &&
             ping_event_type == kTypePingGateway) {
    ReportResultAndStop(kIssueGatewayUpstream);
  } else {
    LOG(WARNING) << iface_name_ << ": " << __func__
                 << " received unexpected event type " << ping_event_type
                 << " while pinging " << address_pinged.ToString();
    ReportResultAndStop(kIssueInternalError);
  }
}

bool ConnectionDiagnostics::DoesPreviousEventMatch(Type type,
                                                   Phase phase,
                                                   Result result,
                                                   size_t num_events_ago) {
  int event_index = diagnostic_events_.size() - 1 - num_events_ago;
  if (event_index < 0) {
    LOG(ERROR) << iface_name_ << ": requested event " << num_events_ago
               << " before the last event, but we only have "
               << diagnostic_events_.size() << " logged";
    return false;
  }

  return (diagnostic_events_[event_index].type == type &&
          diagnostic_events_[event_index].phase == phase &&
          diagnostic_events_[event_index].result == result);
}

}  // namespace shill
