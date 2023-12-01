// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DNS_PROXY_DOH_CURL_CLIENT_H_
#define DNS_PROXY_DOH_CURL_CLIENT_H_

#include <curl/curl.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/callback.h>
#include <base/time/time.h>

namespace dns_proxy {

// List of HTTP status codes.
constexpr int64_t kHTTPOk = 200;
constexpr int64_t kHTTPTooManyRequests = 429;

class DoHCurlClientInterface {
 public:
  // Struct to be returned on a curl request.
  struct CurlResult {
    CurlResult(CURLcode curl_code, int64_t http_code, int64_t retry_delay_ms);

    CURLcode curl_code;
    int64_t http_code;
    int64_t retry_delay_ms;
  };

  // Callback to be invoked back to the client upon request completion.
  // |res| stores the CURL result code, HTTP code, retry delay of the CURL
  // query.
  // |msg| and |len| respectively stores the response and length of the
  // response of the CURL query.
  using QueryCallback = base::RepeatingCallback<void(
      const CurlResult& res, unsigned char* msg, size_t len)>;

  virtual ~DoHCurlClientInterface() = default;

  // Resolve DNS address through DNS-over-HTTPS using DNS query |msg| of size
  // |len| using |name_servers| and |doh_providers|.
  // |callback| will be called upon query completion.
  // |msg| is owned by the caller of this function. The caller is responsible
  // for their lifecycle.
  virtual bool Resolve(const char* msg,
                       int len,
                       const QueryCallback& callback,
                       const std::vector<std::string>& name_servers,
                       const std::string& doh_provider) = 0;
};

// DoHCurlClient receives a wire-format DNS query and re-send it using secure
// DNS (DNS-over-HTTPS). The caller of DoHCurlClient will get a wire-format
// response done through CURL. Given multiple DoH servers, DoHCurlClient will
// query each servers concurrently. It will return only the first successful
// response OR the last failing response.
class DoHCurlClient : public DoHCurlClientInterface {
 public:
  explicit DoHCurlClient(base::TimeDelta timeout);
  DoHCurlClient(const DoHCurlClient&) = delete;
  DoHCurlClient& operator=(const DoHCurlClient&) = delete;
  virtual ~DoHCurlClient();

  // Resolve DNS address through DNS-over-HTTPS using DNS query |msg| of size
  // |len| using |name_servers| and |doh_providers|.
  // |callback| will be called upon query completion.
  // |msg| is owned by the caller of this function. The caller is responsible
  // for their lifecycle.
  // |name_servers| must contain one or more valid IPv4 or IPv6 addresses string
  // such as "8.8.8.8" or "2001:4860:4860::8888".
  // |doh_providers| must contain one or more valid DoH providers string (HTTPS
  // endpoint) such as "https://dns.google/dns-query".
  bool Resolve(const char* msg,
               int len,
               const DoHCurlClientInterface::QueryCallback& callback,
               const std::vector<std::string>& name_servers,
               const std::string& doh_provider) override;

  // Returns a weak pointer to ensure that callbacks don't run after this class
  // is destroyed.
  base::WeakPtr<DoHCurlClient> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

 private:
  // State of an individual query.
  struct State {
    State(CURL* curl, const QueryCallback& callback);
    ~State();

    // Fetch the necessary response and run |callback|.
    void RunCallback(CURLMsg* curl_msg, int64_t http_code);

    // Set DNS response |msg| of length |len| to |response|.
    void SetResponse(char* msg, size_t len);

    // Stores the CURL handle for the query.
    CURL* curl;

    // Stores the response of a query.
    std::vector<uint8_t> response;

    // Stores the header response.
    std::vector<std::string> header;

    // |callback| to be invoked back to the client upon request completion.
    QueryCallback callback;

    // |header_list| is owned by this struct. It is stored here in order to
    // free it when the request is done.
    curl_slist* header_list;
  };

  // Initialize CURL handle to resolve wire-format data |data| of length |len|.
  // This is done by querying DoH provider |doh_provider|.
  // A state containing the CURL handle will be allocated and used to store
  // CURL data such as header list and response.
  // Lifecycle of the state is handled by the caller of this function.
  std::unique_ptr<State> InitCurl(const std::string& doh_provider,
                                  const char* msg,
                                  int len,
                                  const QueryCallback& callback,
                                  const std::vector<std::string>& name_servers);

  // Callback informed about what to wait for. When called, register or remove
  // the socket given from watchers.
  // This method signature matches CURL `socket_callback(...)`.
  // This callback is registered through CURL.
  // |userp| is owned by DoHCurlClient and should be cleaned properly upon
  // query completion.
  static int SocketCallback(CURL* easy,
                            curl_socket_t socket_fd,
                            int what,
                            void* userp,
                            void* socketp);

  // Callback necessary for CURL to write data, method signature matches CURL
  // `write_callback(...)`. This callback is registered through CURL.
  //
  // This callback function gets called by libcurl as soon as there is data
  // received that needs to be saved. For most transfers, this callback gets
  // called many times and each invoke delivers another chunk of data.
  // |ptr| points to the delivered data, and the size of that data is |nmemb|.
  // |size| is always 1. |userdata| refers to the data given to CURL through
  // CURLOPT_WRITEDATA option.
  //
  // |ptr| is owned by CURL and must not be altered in this function.
  // |userdata| is owned by DoHCurlClient and should be cleaned properly upon
  // query completion.
  static size_t WriteCallback(char* ptr,
                              size_t size,
                              size_t nmemb,
                              void* userdata);

  // Callback necessary for CURL to write header data.
  static size_t HeaderCallback(char* data,
                               size_t len,
                               size_t nitems,
                               void* userp);

  // Callback informed when a query timed out.
  void TimeoutCallback();

  // Callback informed to start the query and to handle timeout, method
  // signature matches CURL `timer_callback(...)`. This callback is registered
  // through CURL.
  //
  // |timeout_ms| value of -1 passed to this callback means the caller should
  // delete the timer. All other values are valid expire times, in milliseconds.
  // |userp| refers to the pointer given to CURL through CURLMOPT_TIMERDATA
  // option.
  //
  // |userp| is owned by DoHCurlClient and should be cleaned properly upon
  // query completion.
  //
  // This method is directly passed to CURL as a pointer / void data with long
  // as the expected parameter. Don't change the data type (b/278499652).
  static int TimerCallback(CURLM* multi,
                           long timeout_ms,  // NOLINT(runtime/int)
                           void* userp);

  // Methods to update CURL socket watchers for asynchronous CURL events.
  // When an action is observed, `CheckMultiInfo()` will be called.
  void AddReadWatcher(curl_socket_t socket_fd);
  void AddWriteWatcher(curl_socket_t socket_fd);
  void RemoveWatcher(curl_socket_t socket_fd);

  // Callback called whenever an event is ready to be handled by CURL on
  // |socket_fd|. This callback is registered through the core event loop.
  void OnFileCanReadWithoutBlocking(curl_socket_t socket_fd);
  void OnFileCanWriteWithoutBlocking(curl_socket_t socket_fd);

  // Checks for a querycompletion and handles its result.
  // These functions are called when CURL just finished processing an event.
  // |curl_msg| is owned by CURL, DoHCurlClient should not care about its
  // lifecycle.
  void CheckMultiInfo();
  void HandleResult(CURLMsg* curl_msg);

  // Cancel an in-flight request denoted by a set of states |states|.
  void CancelRequest(const std::set<State*>& states);

  // Cancel in-flight request of identifier |request_id|.
  void CancelRequest(int request_id);

  // Timeout for a CURL query in seconds.
  int64_t timeout_seconds_;

  // Watchers for available event to be handled by CURL.
  std::map<curl_socket_t,
           std::unique_ptr<base::FileDescriptorWatcher::Controller>>
      read_watchers_;
  std::map<curl_socket_t,
           std::unique_ptr<base::FileDescriptorWatcher::Controller>>
      write_watchers_;

  // Current query's states keyed by it's CURL handle.
  std::map<CURL*, std::unique_ptr<State>> states_;

  // CURL multi handle to do asynchronous requests.
  CURLM* curlm_;

  base::WeakPtrFactory<DoHCurlClient> weak_factory_{this};
};
}  // namespace dns_proxy

#endif  // DNS_PROXY_DOH_CURL_CLIENT_H_
