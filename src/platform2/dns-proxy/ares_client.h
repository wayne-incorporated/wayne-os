// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DNS_PROXY_ARES_CLIENT_H_
#define DNS_PROXY_ARES_CLIENT_H_

#include <ares.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/time/time.h>

namespace dns_proxy {

// AresClient resolves DNS queries by forwarding wire-format DNS queries to the
// assigned servers, concurrently.
// The caller of AresClient will get a wire-format response done through ares.
// Given multiple DNS servers, AresClient will query each servers concurrently.
// It will return only the first successful response OR the last failing
// response.
class AresClient {
 public:
  // Callback to be invoked back to the client upon request completion.
  // |status| stores the ares result of the ares query.
  // |msg| and |len| respectively stores the response and length of the
  // response of the ares query.
  using QueryCallback =
      base::RepeatingCallback<void(int status, unsigned char* msg, size_t len)>;

  explicit AresClient(base::TimeDelta timeout);
  virtual ~AresClient();

  // Resolve DNS address using wire-format data |data| of size |len| with
  // |name_servers|.
  // |msg| is owned by the caller of this function. The caller is
  // responsible for their lifecycle.
  // |type| is the socket protocol used, either SOCK_STREAM or SOCK_DGRAM.
  // |name_servers| must contain one or more valid IPv4 or IPv6 addresses string
  // such as "8.8.8.8" or "2001:4860:4860::8888".
  // The callback will return the wire-format response.
  // See: |QueryCallback|
  virtual bool Resolve(const unsigned char* msg,
                       size_t len,
                       const QueryCallback& callback,
                       const std::string& name_servers,
                       int type = SOCK_DGRAM);

 private:
  // State of an individual request.
  struct State {
    State(AresClient* client,
          ares_channel channel,
          const QueryCallback& callback);

    // |client| holds the current class holding this state.
    AresClient* client;

    // Upon calling resolve, all available name servers will be queried
    // concurrently. |channel| is a communications channel that holds the
    // queries.
    ares_channel channel;

    // |callback| to be invoked back to the client upon request completion.
    QueryCallback callback;
  };

  // Callback informed about what to wait for. When called, register or remove
  // the socket given from watchers.
  // |msg| is owned by ares, AresClient and the caller of `Resolve(...)` do not
  // need to handle the lifecycle of |msg|.
  static void AresCallback(
      void* ctx, int status, int timeouts, unsigned char* msg, int len);

  // Handle result of `AresCallback(...)`. Running ares functions on the
  // callback results in an undefined behavior, use another function
  // instead.
  void HandleResult(State* state,
                    int status,
                    std::unique_ptr<uint8_t[]> msg,
                    int len);

  // Process an ares event for |channel|. If |read_fd| or |write_fd| is passed,
  // it checks for a read or write event for the fd. Otherwise, it checks for
  // the timeout in the |channel|.
  void ProcessFd(ares_channel channel,
                 ares_socket_t write_fd,
                 ares_socket_t read_fd);

  // Reset the current timeout callback and process all timed out requests.
  void ResetTimeout(ares_channel channel);

  // Initialize an ares channel. This will used for holding multiple concurrent
  // queries.
  // |type| is the socket protocol used, either SOCK_STREAM or SOCK_DGRAM.
  ares_channel InitChannel(const std::string& name_server, int type);

  // Stop watching file descriptors given by ares's channel |channel|. This must
  // be done before any ares processing because ares might close the watched
  // fd. Watching a closed fd is discouraged for potentially dangerous race
  // condition with a newly created fd.
  void ClearWatchers(ares_channel channel);

  // Update file descriptors to be watched.
  // |read_watchers_| and |write_watchers_| stores the watchers.
  // Because there is no callback to know unused ares sockets, update the
  // watchers whenever:
  // - a query is started,
  // - an action is done for any ares socket.
  //
  // Whenever this is called, |read_watchers_| and |write_watchers_| will
  // be cleared and reset to sockets that needs to be watched.
  void UpdateWatchers(ares_channel channel);

  // Vector of watchers. This will be reconstructed on each ares action.
  // See `UpdateWatchers(...)` on how the values are set and cleared.
  std::map<
      ares_channel,
      std::vector<std::unique_ptr<base::FileDescriptorWatcher::Controller>>>
      read_watchers_;
  std::map<
      ares_channel,
      std::vector<std::unique_ptr<base::FileDescriptorWatcher::Controller>>>
      write_watchers_;

  // Timeout for an ares query.
  base::TimeDelta timeout_;

  // |channels_inflight_| stores all active channels.
  // A channel will be added to the set when it is created and will be removed
  // from the set when it is destroyed.
  // This will be used for callbacks to know whether a request is completed.
  std::set<ares_channel> channels_inflight_;

  base::WeakPtrFactory<AresClient> weak_factory_{this};
};
}  // namespace dns_proxy

#endif  // DNS_PROXY_ARES_CLIENT_H_
