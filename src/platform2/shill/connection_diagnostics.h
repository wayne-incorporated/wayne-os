// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CONNECTION_DIAGNOSTICS_H_
#define SHILL_CONNECTION_DIAGNOSTICS_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>

#include "shill/mockable.h"
#include "shill/net/ip_address.h"

namespace shill {

class DnsClient;
class Error;
class EventDispatcher;
class HttpUrl;
class IcmpSession;
class IcmpSessionFactory;
class Metrics;

// Given a connected Network and a URL, ConnectionDiagnostics performs the
// following actions to diagnose a connectivity problem on the current
// Connection:
// (A) Starts by pinging all DNS servers.
//     (B) If none of the DNS servers reply to pings, then we might have a
//         problem reaching DNS servers. Check if the gateway can be pinged
//         (step I).
//     (C) If at least one DNS server replies to pings but we are out of DNS
//         retries, the DNS servers are at fault. END.
//     (D) If at least one DNS server replies to pings, and we have DNS
//         retries left, resolve the IP of the target web server via DNS.
//         (E) If DNS resolution fails because of a timeout, ping all DNS
//             servers again and find a new reachable DNS server (step A).
//         (F) If DNS resolution fails for any other reason, we have found a
//             DNS server issue. END.
//         (G) Otherwise, ping the IP address of the target web server.
//             (H) If ping is successful, we can reach the target web server. We
//                 might have a HTTP issue or a broken portal. END.
//             (I) If ping is unsuccessful, ping the IP address of the gateway.
//                 (J) If the local gateway respond to pings, then we have
//                     found an upstream connectivity problem or gateway
//                     problem. END.
//                 (K) If there is no response, then the local gateway may not
//                     be responding to pings, or it may not exist on the local
//                     network or be unreachable if there are link layer issues.
//                     END.
//
// TODO(samueltan): Step F: if retry succeeds, remove the unresponsive DNS
// servers so Chrome does not try to use them.
class ConnectionDiagnostics {
 public:
  // The ConnectionDiagnostics::kEventNames string array depends on this enum.
  // Any changes to this enum should be synced with that array.
  enum Type {
    kTypePingDNSServers = 1,
    kTypeResolveTargetServerIP = 2,
    kTypePingTargetServer = 3,
    kTypePingGateway = 4,
  };

  // The ConnectionDiagnostics::kPhaseNames string array depends on this enum.
  // Any changes to this enum should be synced with that array.
  enum Phase {
    kPhaseStart = 0,
    kPhaseEnd = 1,
  };

  // The ConnectionDiagnostics::kResultNames string array depends on this enum.
  // Any changes to this enum should be synced with that array.
  enum Result { kResultSuccess = 0, kResultFailure = 1, kResultTimeout = 2 };

  struct Event {
    Event(Type type_in,
          Phase phase_in,
          Result result_in,
          const std::string& message_in)
        : type(type_in),
          phase(phase_in),
          result(result_in),
          message(message_in) {}
    Type type;
    Phase phase;
    Result result;
    std::string message;
  };

  // The result of the diagnostics is a string describing the connection issue
  // detected (if any), and list of events (e.g. routing table
  // lookup, DNS resolution) performed during the diagnostics.
  using ResultCallback =
      base::OnceCallback<void(const std::string&, const std::vector<Event>&)>;

  // TODO(b/229309479) Remove obsolete descriptions.
  // Metrics::NotifyConnectionDiagnosticsIssue depends on these kIssue strings.
  // Any changes to these strings should be synced with that Metrics function.
  static const char kIssueIPCollision[];
  static const char kIssueRouting[];
  static const char kIssueHTTP[];
  static const char kIssueDNSServerMisconfig[];
  static const char kIssueDNSServerNoResponse[];
  static const char kIssueNoDNSServersConfigured[];
  static const char kIssueDNSServersInvalid[];
  static const char kIssueNone[];
  static const char kIssueGatewayUpstream[];
  static const char kIssueGatewayNotResponding[];
  static const char kIssueServerNotResponding[];
  static const char kIssueGatewayArpFailed[];
  static const char kIssueServerArpFailed[];
  static const char kIssueInternalError[];
  static const char kIssueGatewayNoNeighborEntry[];
  static const char kIssueServerNoNeighborEntry[];
  static const char kIssueGatewayNeighborEntryNotConnected[];
  static const char kIssueServerNeighborEntryNotConnected[];

  ConnectionDiagnostics(std::string iface_name,
                        int iface_index,
                        const IPAddress& ip_address,
                        const IPAddress& gateway,
                        const std::vector<std::string>& dns_list,
                        EventDispatcher* dispatcher,
                        Metrics* metrics,
                        ResultCallback result_callback);
  ConnectionDiagnostics(const ConnectionDiagnostics&) = delete;
  ConnectionDiagnostics& operator=(const ConnectionDiagnostics&) = delete;

  virtual ~ConnectionDiagnostics();

  // Performs connectivity diagnostics for the hostname of the URL |url_string|.
  mockable bool Start(const std::string& url_string);
  void Stop();

  // Returns a string representation of |event|.
  static std::string EventToString(const Event& event);

  bool running() const { return running_; }

 private:
  friend class ConnectionDiagnosticsTest;

  static const int kMaxDNSRetries;

  // Create a new Event with |type|, |phase|, |result|, and an empty message,
  // and add it to the end of |diagnostic_events_|.
  void AddEvent(Type type, Phase phase, Result result);

  // Same as ConnectionDiagnostics::AddEvent, except that the added event
  // contains the string |message|.
  void AddEventWithMessage(Type type,
                           Phase phase,
                           Result result,
                           const std::string& message);

  // Calls |result_callback_|, then stops connection diagnostics.
  // |diagnostic_events_| and |issue| are passed as arguments to
  // |result_callback_| to report the results of the diagnostics.
  void ReportResultAndStop(const std::string& issue);

  // Attempts to resolve the IP address of the hostname of |target_url_| using
  // |dns_list|.
  void ResolveTargetServerIPAddress(const std::vector<std::string>& dns_list);

  // Pings all the DNS servers of |dns_list_|.
  void PingDNSServers();

  // Starts an IcmpSession with |address|. Called when we want to ping the
  // target web server or local gateway.
  void PingHost(const IPAddress& address);

  // Called after each IcmpSession started in
  // ConnectionDiagnostics::PingDNSServers finishes or times out. The DNS server
  // that was pinged can be uniquely identified with |dns_server_index|.
  // Attempts to resolve the IP address of the hostname of |target_url_| again
  // if at least one DNS server was pinged successfully, and if
  // |num_dns_attempts_| has not yet reached |kMaxDNSRetries|.
  void OnPingDNSServerComplete(int dns_server_index,
                               const std::vector<base::TimeDelta>& result);

  // Called after the DNS IP address resolution on started in
  // ConnectionDiagnostics::ResolveTargetServerIPAddress completes.
  void OnDNSResolutionComplete(const Error& error, const IPAddress& address);

  // Called after the IcmpSession started in ConnectionDiagnostics::PingHost on
  // |address_pinged| finishes or times out. |ping_event_type| indicates the
  // type of ping that was started (gateway or target web server), and |result|
  // is the result of the IcmpSession.
  void OnPingHostComplete(Type ping_event_type,
                          const IPAddress& address_pinged,
                          const std::vector<base::TimeDelta>& result);

  // Utility function that returns true iff the event in |diagnostic_events_|
  // that is |num_events_ago| before the last event has a matching |type|,
  // |phase|, and |result|.
  bool DoesPreviousEventMatch(Type type,
                              Phase phase,
                              Result result,
                              size_t num_events_ago);

  EventDispatcher* dispatcher_;
  Metrics* metrics_;

  // The name of the network interface associated with the connection.
  std::string iface_name_;
  // The index of the network interface associated with the connection.
  int iface_index_;
  // The IP address of the network interface to use for the diagnostic.
  IPAddress ip_address_;
  // The IP address of the gateway.
  IPAddress gateway_;
  std::vector<std::string> dns_list_;

  std::unique_ptr<DnsClient> dns_client_;
  std::unique_ptr<IcmpSession> icmp_session_;

  // The URL whose hostname is being diagnosed. Stored in unique_ptr so that it
  // can be cleared when we stop diagnostics.
  std::unique_ptr<HttpUrl> target_url_;

  // Used to ping multiple DNS servers in parallel.
  std::map<int, std::unique_ptr<IcmpSession>>
      id_to_pending_dns_server_icmp_session_;
  std::vector<std::string> pingable_dns_servers_;

  int num_dns_attempts_;
  bool running_;

  ResultCallback result_callback_;

  // Record of all diagnostic events that occurred, sorted in order of
  // occurrence.
  std::vector<Event> diagnostic_events_;

  base::WeakPtrFactory<ConnectionDiagnostics> weak_ptr_factory_;
};

}  // namespace shill

#endif  // SHILL_CONNECTION_DIAGNOSTICS_H_
