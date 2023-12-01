// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dns-proxy/doh_curl_client.h"

#include <utility>

#include <base/containers/contains.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_runner.h>

namespace dns_proxy {
namespace {
constexpr char kLinuxUserAgent[] =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (kHTML, like Gecko) "
    "Chrome/7.0.38.09.132 Safari/537.36";
constexpr std::array<const char*, 2> kDoHHeaderList{
    {"Accept: application/dns-message",
     "Content-Type: application/dns-message"}};
}  // namespace

DoHCurlClient::CurlResult::CurlResult(CURLcode curl_code,
                                      int64_t http_code,
                                      int64_t retry_delay_ms)
    : curl_code(curl_code),
      http_code(http_code),
      retry_delay_ms(retry_delay_ms) {}

DoHCurlClient::State::State(CURL* curl, const QueryCallback& callback)
    : curl(curl), callback(callback), header_list(nullptr) {}

DoHCurlClient::State::~State() {
  curl_easy_cleanup(curl);
  curl_slist_free_all(header_list);
}

void DoHCurlClient::State::RunCallback(CURLMsg* curl_msg, int64_t http_code) {
  // TODO(jasongustaman): Use HTTP 429, Retry-After header value.
  CurlResult res(curl_msg->data.result, http_code, 0 /* retry_delay_ms */);
  callback.Run(res, response.data(), response.size());
}

void DoHCurlClient::State::SetResponse(char* msg, size_t len) {
  if (len <= 0) {
    LOG(ERROR) << "Unexpected length: " << len;
    return;
  }
  response.insert(response.end(), msg, msg + len);
}

DoHCurlClient::DoHCurlClient(base::TimeDelta timeout)
    : timeout_seconds_(timeout.InSeconds()) {
  // Initialize CURL.
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curlm_ = curl_multi_init();

  // Set socket callback to `SocketCallback(...)`. This function will be called
  // whenever a CURL socket state is changed. DoHCurlClient class |this| will
  // passed as a parameter of the callback.
  curl_multi_setopt(curlm_, CURLMOPT_SOCKETDATA, this);
  curl_multi_setopt(curlm_, CURLMOPT_SOCKETFUNCTION,
                    &DoHCurlClient::SocketCallback);

  // Set timer callback to `TimerCallback(...)`. This function will be called
  // whenever a timeout change happened. DoHCurlClient class |this| will be
  // passed as a parameter of the callback.
  curl_multi_setopt(curlm_, CURLMOPT_TIMERDATA, this);
  curl_multi_setopt(curlm_, CURLMOPT_TIMERFUNCTION,
                    &DoHCurlClient::TimerCallback);
}

DoHCurlClient::~DoHCurlClient() {
  // Cancel all in-flight queries.
  for (const auto& state : states_) {
    curl_multi_remove_handle(curlm_, state.first);
  }
  states_.clear();
  curl_multi_cleanup(curlm_);
  curlm_ = nullptr;
  curl_global_cleanup();
}

void DoHCurlClient::HandleResult(CURLMsg* curl_msg) {
  // `HandleResult(...)` may be called even after `CancelRequest(...)` is
  // called. This happens if a query is completed while queries are being
  // cancelled. On such case, do nothing.
  if (!base::Contains(states_, curl_msg->easy_handle)) {
    return;
  }

  CURL* curl = curl_msg->easy_handle;
  State* state = states_[curl].get();

  int64_t http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

  // Run the callback.
  state->RunCallback(curl_msg, http_code);

  // Clean states.
  curl_multi_remove_handle(curlm_, state->curl);
  states_.erase(state->curl);
}

void DoHCurlClient::CheckMultiInfo() {
  CURLMsg* curl_msg = nullptr;
  int msgs_left = 0;
  while ((curl_msg = curl_multi_info_read(curlm_, &msgs_left))) {
    if (curl_msg->msg != CURLMSG_DONE) {
      continue;
    }
    HandleResult(curl_msg);
  }
}

void DoHCurlClient::OnFileCanReadWithoutBlocking(curl_socket_t socket_fd) {
  int still_running;
  CURLMcode rc = curl_multi_socket_action(curlm_, socket_fd, CURL_CSELECT_IN,
                                          &still_running);
  if (rc != CURLM_OK) {
    LOG(ERROR) << "Failed to read from socket: " << curl_multi_strerror(rc);
    return;
  }
  CheckMultiInfo();
}

void DoHCurlClient::OnFileCanWriteWithoutBlocking(curl_socket_t socket_fd) {
  int still_running;
  CURLMcode rc = curl_multi_socket_action(curlm_, socket_fd, CURL_CSELECT_OUT,
                                          &still_running);
  if (rc != CURLM_OK) {
    LOG(ERROR) << "Failed to write to socket: " << curl_multi_strerror(rc);
    return;
  }
  CheckMultiInfo();
}

void DoHCurlClient::AddReadWatcher(curl_socket_t socket_fd) {
  if (!base::Contains(read_watchers_, socket_fd)) {
    read_watchers_.emplace(
        socket_fd,
        base::FileDescriptorWatcher::WatchReadable(
            socket_fd,
            base::BindRepeating(&DoHCurlClient::OnFileCanReadWithoutBlocking,
                                weak_factory_.GetWeakPtr(), socket_fd)));
  }
}

void DoHCurlClient::AddWriteWatcher(curl_socket_t socket_fd) {
  if (!base::Contains(write_watchers_, socket_fd)) {
    write_watchers_.emplace(
        socket_fd,
        base::FileDescriptorWatcher::WatchReadable(
            socket_fd,
            base::BindRepeating(&DoHCurlClient::OnFileCanWriteWithoutBlocking,
                                weak_factory_.GetWeakPtr(), socket_fd)));
  }
}

void DoHCurlClient::RemoveWatcher(curl_socket_t socket_fd) {
  read_watchers_.erase(socket_fd);
  write_watchers_.erase(socket_fd);
}

int DoHCurlClient::SocketCallback(
    CURL* easy, curl_socket_t socket_fd, int what, void* userp, void* socketp) {
  DoHCurlClient* client = static_cast<DoHCurlClient*>(userp);
  switch (what) {
    case CURL_POLL_IN:
      client->AddReadWatcher(socket_fd);
      return 0;
    case CURL_POLL_OUT:
      client->AddWriteWatcher(socket_fd);
      return 0;
    case CURL_POLL_INOUT:
      client->AddReadWatcher(socket_fd);
      client->AddWriteWatcher(socket_fd);
      return 0;
    case CURL_POLL_REMOVE:
      client->RemoveWatcher(socket_fd);
      return 0;
    default:
      return 0;
  }
}

void DoHCurlClient::TimeoutCallback() {
  if (!curlm_) {
    return;
  }
  int still_running;
  curl_multi_socket_action(curlm_, CURL_SOCKET_TIMEOUT, 0, &still_running);
  CheckMultiInfo();
}

int DoHCurlClient::TimerCallback(CURLM* multi,
                                 long timeout_ms,  // NOLINT(runtime/int)
                                 void* userp) {
  DoHCurlClient* client = static_cast<DoHCurlClient*>(userp);
  if (timeout_ms > 0) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindRepeating(&DoHCurlClient::TimeoutCallback,
                            client->GetWeakPtr()),
        base::Milliseconds(timeout_ms));
  } else if (timeout_ms == 0) {
    // Libcurl explicitly disallow calling its API directly from it's callback.
    // Post the call such that is run outside the callback.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindRepeating(&DoHCurlClient::TimeoutCallback,
                                       client->GetWeakPtr()));
  }
  return 0;
}

size_t DoHCurlClient::WriteCallback(char* ptr,
                                    size_t size,
                                    size_t nmemb,
                                    void* userdata) {
  State* state = static_cast<State*>(userdata);
  size_t len = size * nmemb;
  state->SetResponse(ptr, len);
  return len;
}

size_t DoHCurlClient::HeaderCallback(char* data,
                                     size_t size,
                                     size_t nitems,
                                     void* userp) {
  State* state = static_cast<State*>(userp);
  size_t len = size * nitems;
  std::string header(data, len);
  state->header.emplace_back(header);
  return len;
}

std::unique_ptr<DoHCurlClient::State> DoHCurlClient::InitCurl(
    const std::string& doh_provider,
    const char* msg,
    int len,
    const QueryCallback& callback,
    const std::vector<std::string>& name_servers) {
  CURL* curl;
  curl = curl_easy_init();
  if (!curl) {
    LOG(ERROR) << "Failed to initialize curl";
    return nullptr;
  }

  // Allocate a state for the request.
  std::unique_ptr<State> state = std::make_unique<State>(curl, callback);

  // Set the target URL which is the DoH provider to query to.
  curl_easy_setopt(curl, CURLOPT_URL, doh_provider.c_str());

  // Set the DNS name servers to resolve the URL(s) / DoH provider(s).
  // This uses ares and will be done asynchronously.
  curl_easy_setopt(curl, CURLOPT_DNS_SERVERS,
                   base::JoinString(name_servers, ",").c_str());

  // Set the HTTP header to the needed DoH header. The stored value needs to
  // be released when query is finished.
  for (int i = 0; i < kDoHHeaderList.size(); i++) {
    state.get()->header_list =
        curl_slist_append(state.get()->header_list, kDoHHeaderList[i]);
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, state.get()->header_list);

  // Stores the data to be sent through HTTP POST and its length.
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, msg);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);

  // Set the user agent for the query.
  curl_easy_setopt(curl, CURLOPT_USERAGENT, kLinuxUserAgent);

  // Ignore signals SIGPIPE to be sent when the other end of CURL socket is
  // closed.
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 0);

  // Set timeout of the query.
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_seconds_);

  // Set the callback to be called whenever CURL got a response. The data
  // needs to be copied to the write data.
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &DoHCurlClient::WriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, state.get());

  // Handle redirection automatically.
  curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);

  return state;
}

bool DoHCurlClient::Resolve(const char* msg,
                            int len,
                            const QueryCallback& callback,
                            const std::vector<std::string>& name_servers,
                            const std::string& doh_provider) {
  std::unique_ptr<State> state =
      InitCurl(doh_provider, msg, len, callback, name_servers);
  if (!state) {
    return false;
  }
  CURL* curl = state->curl;

  // Create state structure to store required data of each query.
  states_.emplace(curl, std::move(state));

  // Runs the query asynchronously.
  curl_multi_add_handle(curlm_, curl);

  return true;
}
}  // namespace dns_proxy
