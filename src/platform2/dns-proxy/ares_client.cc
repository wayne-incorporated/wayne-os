// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dns-proxy/ares_client.h"

#include <algorithm>
#include <utility>

#include <base/containers/contains.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_runner.h>

namespace dns_proxy {
namespace {
// Ares option to do a DNS lookup without trying to check hosts file.
static char kLookupsOpt[] = "b";
}  // namespace

AresClient::State::State(AresClient* client,
                         ares_channel channel,
                         const QueryCallback& callback)
    : client(client), channel(channel), callback(callback) {}

AresClient::AresClient(base::TimeDelta timeout) : timeout_(timeout) {
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    LOG(DFATAL) << "Failed to initialize ares library";
  }
}

AresClient::~AresClient() {
  read_watchers_.clear();
  write_watchers_.clear();
  // Whenever ares_destroy is called, AresCallback will be called with status
  // equal to ARES_EDESTRUCTION. This callback ensures that the states of the
  // queries are cleared properly.
  for (const auto& channel : channels_inflight_) {
    ares_destroy(channel);
  }
  ares_library_cleanup();
}

void AresClient::ProcessFd(ares_channel channel,
                           ares_socket_t read_fd,
                           ares_socket_t write_fd) {
  // Remove the watchers before ares potentially closing the watched fd in
  // ares_process_fd. Watching a closed fd is discouraged.
  ClearWatchers(channel);
  ares_process_fd(channel, read_fd, write_fd);
  UpdateWatchers(channel);
}

void AresClient::ClearWatchers(ares_channel channel) {
  read_watchers_.erase(channel);
  write_watchers_.erase(channel);
}

void AresClient::UpdateWatchers(ares_channel channel) {
  // Only update watchers if the channel is still valid.
  if (!base::Contains(channels_inflight_, channel)) {
    return;
  }

  // Rebuild the watchers. This is necessary because ares does not provide a
  // utility to notify for unused sockets.
  const auto& [read_watchers, read_emplaced] = read_watchers_.emplace(
      channel,
      std::vector<std::unique_ptr<base::FileDescriptorWatcher::Controller>>());
  const auto& [write_watchers, write_emplaced] = write_watchers_.emplace(
      channel,
      std::vector<std::unique_ptr<base::FileDescriptorWatcher::Controller>>());

  ares_socket_t sockets[ARES_GETSOCK_MAXNUM];
  int action_bits = ares_getsock(channel, sockets, ARES_GETSOCK_MAXNUM);
  for (int i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
    if (ARES_GETSOCK_READABLE(action_bits, i)) {
      read_watchers->second.emplace_back(
          base::FileDescriptorWatcher::WatchReadable(
              sockets[i],
              base::BindRepeating(&AresClient::ProcessFd,
                                  weak_factory_.GetWeakPtr(), channel,
                                  sockets[i], ARES_SOCKET_BAD)));
    }
    if (ARES_GETSOCK_WRITABLE(action_bits, i)) {
      write_watchers->second.emplace_back(
          base::FileDescriptorWatcher::WatchWritable(
              sockets[i],
              base::BindRepeating(&AresClient::ProcessFd,
                                  weak_factory_.GetWeakPtr(), channel,
                                  ARES_SOCKET_BAD, sockets[i])));
    }
  }
}

void AresClient::AresCallback(
    void* ctx, int status, int timeouts, unsigned char* msg, int len) {
  State* state = static_cast<State*>(ctx);
  // The query is cancelled in-flight. Cleanup the state.
  if (status == ARES_ECANCELLED || status == ARES_EDESTRUCTION) {
    delete state;
    return;
  }

  auto buf = std::make_unique<unsigned char[]>(len);
  memcpy(buf.get(), msg, len);
  // Handle the result outside this function to avoid undefined behaviors.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&AresClient::HandleResult,
                                state->client->weak_factory_.GetWeakPtr(),
                                state, status, std::move(buf), len));
}

void AresClient::HandleResult(State* state,
                              int status,
                              std::unique_ptr<uint8_t[]> msg,
                              int len) {
  // Set state as unique pointer to force cleanup, the state must be destroyed
  // in this function.
  std::unique_ptr<State> scoped_state(state);

  // `HandleResult(...)` may be called even after ares channel is destroyed
  // This happens if a query is completed while queries are being cancelled.
  // On such case, do nothing, the state will be deleted through unique pointer.
  const auto& channel_inflight = channels_inflight_.find(state->channel);
  if (channel_inflight == channels_inflight_.end()) {
    return;
  }

  // Run the callback.
  state->callback.Run(status, msg.get(), len);
  msg.reset();

  // Cleanup the states.
  channels_inflight_.erase(state->channel);
  read_watchers_.erase(state->channel);
  write_watchers_.erase(state->channel);
  ares_destroy(state->channel);
}

void AresClient::ResetTimeout(ares_channel channel) {
  // Check for timeout if the channel is still available.
  if (!base::Contains(channels_inflight_, channel)) {
    return;
  }
  ProcessFd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

  struct timeval max_tv, ret_tv;
  struct timeval* tv;
  max_tv.tv_sec = timeout_.InMilliseconds() / 1000;
  max_tv.tv_usec = (timeout_.InMilliseconds() % 1000) * 1000;
  if ((tv = ares_timeout(channel, &max_tv, &ret_tv)) == NULL) {
    LOG(ERROR) << "Failed to get timeout";
    return;
  }
  int timeout_ms = tv->tv_sec * 1000 + tv->tv_usec / 1000;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindRepeating(&AresClient::ResetTimeout, weak_factory_.GetWeakPtr(),
                          channel),
      base::Milliseconds(timeout_ms));
}

ares_channel AresClient::InitChannel(const std::string& name_server, int type) {
  struct ares_options options;
  memset(&options, 0, sizeof(options));
  int optmask = 0;

  // Set option timeout.
  optmask |= ARES_OPT_TIMEOUTMS;
  options.timeout = timeout_.InMilliseconds();

  // Set maximum number of retries.
  optmask |= ARES_OPT_TRIES;
  options.tries = 1;

  // Explicitly supply ares option values below to avoid having ares read
  // /etc/resolv.conf.
  // The client is responsible for honoring the value inside /etc/resolv.conf.
  // Number of servers to query. This will be overridden by the function
  // ares_set_servers_csv below.
  optmask |= ARES_OPT_SERVERS;
  options.nservers = 0;
  // Ares should not use any search domains as it is only proxying packets.
  optmask |= ARES_OPT_DOMAINS;
  options.ndomains = 0;
  // Order of the result should not matter.
  optmask |= ARES_OPT_SORTLIST;
  options.nsort = 0;
  // Only do DNS lookup without checking hosts file.
  optmask |= ARES_OPT_LOOKUPS;
  options.lookups = kLookupsOpt;
  // Option to check number of dots before using search domains. This is not
  // used as we don't use search domains.
  optmask |= ARES_OPT_NDOTS;
  options.ndots = 1;

  // Allow c-ares to use flags.
  optmask |= ARES_OPT_FLAGS;

  // Send the query using the original protocol used.
  if (type == SOCK_DGRAM) {
    // Disable TCP fallback. Whenever a TCP fallback is necessary, instead of
    // having ares redo the query through TCP, return the response to client
    // as-is. The client is responsible to retry with TCP.
    options.flags |= ARES_FLAG_IGNTC;
  } else {
    // Force to use TCP.
    options.flags |= ARES_FLAG_USEVC;
  }

  // Return the result as-is without checking the response. This is done in
  // order for the caller of ares client to get the failing query result.
  options.flags |= ARES_FLAG_NOCHECKRESP;

  ares_channel channel;
  if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
    LOG(ERROR) << "Failed to initialize ares_channel";
    ares_destroy(channel);
    return nullptr;
  }

  if (ares_set_servers_csv(channel, name_server.c_str()) != ARES_SUCCESS) {
    LOG(ERROR) << "Failed to set ares name server";
    ares_destroy(channel);
    return nullptr;
  }

  return channel;
}

bool AresClient::Resolve(const unsigned char* msg,
                         size_t len,
                         const QueryCallback& callback,
                         const std::string& name_server,
                         int type) {
  ares_channel channel = InitChannel(name_server, type);
  if (!channel)
    return false;

  State* state = new State(this, channel, callback);
  ares_send(channel, msg, len, &AresClient::AresCallback, state);

  // Start timeout handler.
  channels_inflight_.emplace(channel);
  UpdateWatchers(channel);
  ResetTimeout(channel);

  return true;
}
}  // namespace dns_proxy
