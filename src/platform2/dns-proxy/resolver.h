// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DNS_PROXY_RESOLVER_H_
#define DNS_PROXY_RESOLVER_H_

#include <sys/socket.h>

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <chromeos/patchpanel/dns/dns_response.h>
#include <chromeos/patchpanel/socket.h>

#include "dns-proxy/ares_client.h"
#include "dns-proxy/doh_curl_client.h"
#include "dns-proxy/metrics.h"

namespace dns_proxy {

// |kDNSBufSize| holds the maximum size of a DNS message which is the maximum
// size of a TCP packet.
constexpr uint32_t kDNSBufSize = 65536;

// Resolver receives wire-format DNS queries and proxies them to DNS server(s).
// This class supports standard plain-text resolving using c-ares and secure
// DNS / DNS-over-HTTPS (DoH) using CURL.
//
// The resolver supports both plain-text and DoH name resolution. By default,
// standard DNS will be performed using the name servers passed to
// SetNameServers. DNS over HTTPS will be used if secure DNS providers are
// passed to SetDoHProviders. DoH can either be "always on" or "opportunistic".
// In the case of the former, only DNS over HTTPS will be performed and failures
// are final. In the case of latter, if DNS over HTTP fails, it will fall back
// to standard plain-text DNS.
//
// Resolver listens on UDP and TCP port 53.
class Resolver {
 public:
  // |SocketFd| stores client's socket data.
  // This is used to send reply to the client on callback called.
  struct SocketFd {
    SocketFd(int type, int fd);

    // |type| is either SOCK_STREAM or SOCK_DGRAM.
    const int type;
    const int fd;

    // Store the data and length of the query to retry failing queries.
    // For TCP, DNS has an additional 2-bytes header representing the length
    // of the query. In order to make the data 4-bytes aligned, a pointer |msg|
    // for buffer |buf| is used. |len| denotes the length of |msg|.
    char* msg;
    ssize_t len;

    // Holds the source address of the client and it's address length.
    // At initialization, |socklen| value will be the size of |src|. Upon
    // receiving, |socklen| should be updated to be the size of the address
    // of |src|.
    // For TCP connections, |src| and |len| are not used.
    struct sockaddr_storage src;
    socklen_t socklen;

    // Underlying buffer of |data|.
    char buf[kDNSBufSize];

    // Number of attempted retry. Query should not be retried when reaching
    // a certain threshold.
    int num_retries;

    // Number of currently running queries.
    int num_active_queries;

    // Identifier for the socket. |fd| is not a suitable identifier here as it
    // can be used for multiple SocketFds.
    const int id;

    // Records timings for metrics.
    Metrics::QueryTimer timer;
    base::WeakPtrFactory<SocketFd> weak_factory{this};
  };

  // |ProbeState| is used to store the probe state of a DoH provider or name
  // server. For example, when a probe succeeds for a specific name server,
  // subsequent probing that refers to the same state will be disabled.
  // The same applies for invalidating a name server. If a query resulted in
  // a failure, but the query is done prior to the name server being validated,
  // the name server will not be invalidated.
  struct ProbeState {
    ProbeState(const std::string& target, bool doh, bool validated = false);

    // |target| is the DoH provider or name server used for the probe.
    // |doh| defines whether target is a DoH provider or a name server.
    std::string target;
    bool doh;

    bool validated;
    int num_retries;
    base::WeakPtrFactory<ProbeState> weak_factory{this};
  };

  // |ProbeData| stores required data of a DoH or Do53 probe to record metrics
  // and logs.
  struct ProbeData {
    sa_family_t family;
    int num_retries;
    base::Time start_time;
  };

  Resolver(base::RepeatingCallback<void(std::ostream& stream)> logger,
           base::TimeDelta timeout,
           base::TimeDelta retry_delay,
           int max_num_retries);
  // Provided for testing only.
  Resolver(std::unique_ptr<AresClient> ares_client,
           std::unique_ptr<DoHCurlClientInterface> curl_client,
           bool disable_probe = true,
           std::unique_ptr<Metrics> metrics = nullptr);
  virtual ~Resolver() = default;

  // Listen on an incoming DNS query on address |addr| for UDP and TCP.
  // Listening on default DNS port (53) requires CAP_NET_BIND_SERVICE.
  virtual bool ListenTCP(struct sockaddr* addr);
  virtual bool ListenUDP(struct sockaddr* addr);

  // Set standard DNS and DNS-over-HTTPS servers endpoints.
  // If DoH servers are not empty, resolving domain will be done with DoH.
  // |always_on_doh| flag is used to disallow fallback to standard plain-text
  // DNS.
  virtual void SetNameServers(const std::vector<std::string>& name_servers);
  virtual void SetDoHProviders(const std::vector<std::string>& doh_providers,
                               bool always_on_doh = false);

  // Handle DNS results queried through ares.
  // |sock_fd| is the socket data needed to reply to the client. Empty
  // |sock_fd| means that the request is already handled.
  // |probe_state| stores the current probing state including the name server
  // used for the query. Upon failure, if |probe_state| is valid, the name
  // server should be invalidated.
  // This function passed the first successful result or the last result back
  // to the client.
  //
  // |status| is the ares response status. |msg| is the wire-format response
  // of the DNS query given through `Resolve(...)` with the len |len|.
  // |msg| and its lifecycle is owned by ares.
  void HandleAresResult(base::WeakPtr<SocketFd> sock_fd,
                        base::WeakPtr<ProbeState> probe_state,
                        int status,
                        unsigned char* msg,
                        size_t len);

  // Handle DoH results queried through curl.
  // |sock_fd| is the socket data needed to reply to the client. Empty
  // |sock_fd| means that the request is already handled.
  // |probe_state| stores the current probing state including the DoH provider
  // used for the query. Upon failure, if |probe_state| is valid, the DoH
  // provider should be invalidated.
  // This function passed the first successful result or the last result back
  // to the client.
  //
  // |http_code| is the HTTP status code of the response. |msg| is the
  // wire-format response of the DNS query given through `Resolve(...)` with
  // the len |len|. |msg| and its lifecycle is owned by DoHCurlClient.
  void HandleCurlResult(base::WeakPtr<SocketFd> sock_fd,
                        base::WeakPtr<ProbeState> probe_state,
                        const DoHCurlClient::CurlResult& res,
                        unsigned char* msg,
                        size_t len);

  // Resolve a domain using CURL or Ares using data from |sock_fd|.
  // If |fallback| is true, force to use standard plain-text DNS.
  void Resolve(base::WeakPtr<SocketFd> sock_fd, bool fallback = false);

  // Handle DoH and Do53 probe result from the DoH provider or name server
  // provided inside |probe_state|. |probe_state| also defines the current
  // probing state, including if it is already successful. If the probe is
  // successful, the provider or name server will be validated.
  // For Do53, |data| is added for metrics, including IP family.
  void HandleDoHProbeResult(base::WeakPtr<ProbeState> probe_state,
                            const ProbeData& probe_data,
                            const DoHCurlClient::CurlResult& res,
                            unsigned char* msg,
                            size_t len);
  void HandleDo53ProbeResult(base::WeakPtr<ProbeState> probe_state,
                             const ProbeData& probe_data,
                             int status,
                             unsigned char* msg,
                             size_t len);

  // Create a SERVFAIL response from a DNS query |msg| of length |len|.
  patchpanel::DnsResponse ConstructServFailResponse(const char* msg, int len);

  // Provided for testing only. Enable or disable probing.
  void SetProbingEnabled(bool enable_probe);

  friend std::ostream& operator<<(std::ostream& stream,
                                  const Resolver& resolver);

 private:
  // |TCPConnection| is used to track and terminate TCP connections.
  struct TCPConnection {
    TCPConnection(std::unique_ptr<patchpanel::Socket> sock,
                  const base::RepeatingCallback<void(int, int)>& callback);

    std::unique_ptr<patchpanel::Socket> sock;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher;
  };

  // Callback to handle newly opened connections on TCP sockets.
  void OnTCPConnection();

  // Handle DNS query from clients. |type| values will be either SOCK_DGRAM
  // or SOCK STREAM, for UDP and TCP respectively.
  void OnDNSQuery(int fd, int type);

  // Send back data taken from CURL or Ares to the client.
  void ReplyDNS(base::WeakPtr<SocketFd> sock_fd,
                unsigned char* msg,
                size_t len);

  // Set either name servers or DoH providers |targets| based on the boolean
  // type |doh|.
  void SetServers(const std::vector<std::string>& targets, bool doh);

  // Resolve a domain using CURL or Ares using data from |sock_fd|.
  bool ResolveDNS(base::WeakPtr<SocketFd> sock_fd, bool doh);

  // Get the active DoH providers / name servers. It will try to return the
  // validated DoH providers / name servers unless there are none.
  // The behavior is then slightly different for each modes:
  // - DoH off: return all name servers.
  // - DoH automatic: return empty DoH providers (should behave like DoH off).
  // - DoH always on: return all DoH providers.
  std::vector<std::string> GetActiveDoHProviders();
  std::vector<std::string> GetActiveNameServers();

  // Restart probe upon DNS query failure. |probe_state| store the data needed
  // for probing, DoH provider or name server. |probe_state| is invalidated
  // after this call.
  void RestartProbe(base::WeakPtr<ProbeState> probe_state);

  // Start a probe to validate a DoH provider or name server defines inside
  // |probe_state|. Weak pointer is used here to cancel remaining probes if it
  // is no longer interesting.
  void Probe(base::WeakPtr<ProbeState> probe_state);

  // A logging name for this Resolver to distinguish its logs from lots of other
  // Resolvers owner by other Proxy instances.
  base::RepeatingCallback<void(std::ostream& stream)> logger_;

  // Disallow DoH fallback to standard plain-text DNS.
  bool always_on_doh_;

  // Resolve using DoH if true.
  bool doh_enabled_;

  // Watch |tcp_src_| for incoming TCP connections.
  std::unique_ptr<patchpanel::Socket> tcp_src_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> tcp_src_watcher_;

  // Map of TCP connections keyed by their file descriptor.
  std::map<int, std::unique_ptr<TCPConnection>> tcp_connections_;

  // Watch queries from |udp_src_|.
  std::unique_ptr<patchpanel::Socket> udp_src_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> udp_src_watcher_;

  // Name servers and DoH providers validated through probes.
  std::vector<std::string> validated_name_servers_;
  std::vector<std::string> validated_doh_providers_;

  // Name servers and DoH providers of the underlying network alongside its
  // probe state.
  std::map<std::string, std::unique_ptr<ProbeState>> name_servers_;
  std::map<std::string, std::unique_ptr<ProbeState>> doh_providers_;

  // Provided for testing only. Boolean to disable probe.
  bool disable_probe_ = false;

  // Delay before retrying a failing query.
  base::TimeDelta retry_delay_;

  // Maximum number of retries before giving up.
  int max_num_retries_;

  // Metrics must outlive SocketFd as it is called on SocketFd's destructor.
  std::unique_ptr<Metrics> metrics_;

  // Map of SocketFds keyed by its SocketFd ID.
  std::map<int, std::unique_ptr<SocketFd>> sock_fds_;

  // Ares client to resolve DNS through standard plain-text DNS.
  std::unique_ptr<AresClient> ares_client_;

  // Curl client to resolve DNS through secure DNS.
  std::unique_ptr<DoHCurlClientInterface> curl_client_;

  base::WeakPtrFactory<Resolver> weak_factory_{this};
};
}  // namespace dns_proxy

#endif  // DNS_PROXY_RESOLVER_H_
