// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <base/check_op.h>
#include <brillo/http/http_transport_curl.h>

#include <limits>
#include <optional>
#include <utility>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/http/http_connection_curl.h>
#include <brillo/http/http_request.h>
#include <brillo/strings/string_utils.h>

namespace brillo {
namespace http {
namespace curl {

namespace {
using RepeatingSuccessCallback =
    base::RepeatingCallback<void(RequestID, std::unique_ptr<Response>)>;
using RepeatingErrorCallback =
    base::RepeatingCallback<void(RequestID, const brillo::Error*)>;

// Wraps the given OnceCallback into a RepeatingCallback that relays its
// invocation to the original OnceCallback on the first invocation. The
// following invocations are just ignored.
template <typename... Args>
base::RepeatingCallback<void(Args...)> AdaptOnceCallbackForRepeating(
    base::OnceCallback<void(Args...)> callback) {
  return base::BindRepeating(
      [](base::OnceCallback<void(Args...)>& cb, Args... args) {
        if (!cb.is_null()) {
          std::move(cb).Run(std::forward<Args>(args)...);
        }
      },
      base::OwnedRef(std::move(callback)));
}
}  // namespace

// This is a class that stores connection data on particular CURL socket
// and provides file descriptor watcher to monitor read and/or write operations
// on the socket's file descriptor.
class Transport::SocketPollData {
 public:
  SocketPollData(const std::shared_ptr<CurlInterface>& curl_interface,
                 CURLM* curl_multi_handle,
                 Transport* transport,
                 curl_socket_t socket_fd)
      : curl_interface_(curl_interface),
        curl_multi_handle_(curl_multi_handle),
        transport_(transport),
        socket_fd_(socket_fd) {}
  SocketPollData(const SocketPollData&) = delete;
  SocketPollData& operator=(const SocketPollData&) = delete;

  void StopWatcher() {
    read_watcher_ = nullptr;
    write_watcher_ = nullptr;
  }

  bool WatchReadable() {
    read_watcher_ = base::FileDescriptorWatcher::WatchReadable(
        socket_fd_,
        base::BindRepeating(&Transport::SocketPollData::OnSocketReady,
                            base::Unretained(this), CURL_CSELECT_IN));
    return read_watcher_.get();
  }

  bool WatchWritable() {
    write_watcher_ = base::FileDescriptorWatcher::WatchWritable(
        socket_fd_,
        base::BindRepeating(&Transport::SocketPollData::OnSocketReady,
                            base::Unretained(this), CURL_CSELECT_OUT));
    return write_watcher_.get();
  }

 private:
  // Data on the socket is available to be read from or written to.
  // Notify CURL of the action it needs to take on the socket file descriptor.
  void OnSocketReady(int action) {
    int still_running_count = 0;
    CURLMcode code = curl_interface_->MultiSocketAction(
        curl_multi_handle_, socket_fd_, action, &still_running_count);
    CHECK_NE(CURLM_CALL_MULTI_PERFORM, code)
        << "CURL should no longer return CURLM_CALL_MULTI_PERFORM here";

    if (code == CURLM_OK)
      transport_->ProcessAsyncCurlMessages();
  }

  // The CURL interface to use.
  std::shared_ptr<CurlInterface> curl_interface_;
  // CURL multi-handle associated with the transport.
  CURLM* curl_multi_handle_;
  // Transport object itself.
  Transport* transport_;
  // The socket file descriptor for the connection.
  curl_socket_t socket_fd_;

  std::unique_ptr<base::FileDescriptorWatcher::Controller> read_watcher_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> write_watcher_;
};

// The request data associated with an asynchronous operation on a particular
// connection.
struct Transport::AsyncRequestData {
  // Success/error callbacks to be invoked at the end of the request.
  RepeatingSuccessCallback success_callback;
  RepeatingErrorCallback error_callback;
  // We store a connection here to make sure the object is alive for
  // as long as asynchronous operation is running.
  std::shared_ptr<Connection> connection;
  // The ID of this request.
  RequestID request_id;
};

Transport::Transport(const std::shared_ptr<CurlInterface>& curl_interface)
    : curl_interface_{curl_interface} {
  VLOG(2) << "curl::Transport created";
  UseDefaultCertificate();
}

Transport::Transport(const std::shared_ptr<CurlInterface>& curl_interface,
                     const std::string& proxy)
    : curl_interface_{curl_interface}, proxy_{proxy} {
  VLOG(2) << "curl::Transport created with proxy " << proxy;
  UseDefaultCertificate();
}

Transport::~Transport() {
  ClearHost();
  ShutDownAsyncCurl();
  VLOG(2) << "curl::Transport destroyed";
}

std::shared_ptr<http::Connection> Transport::CreateConnection(
    const std::string& url,
    const std::string& method,
    const HeaderList& headers,
    const std::string& user_agent,
    const std::string& referer,
    brillo::ErrorPtr* error) {
  std::shared_ptr<http::Connection> connection;
  CURL* curl_handle = curl_interface_->EasyInit();
  if (!curl_handle) {
    LOG(ERROR) << "Failed to initialize CURL";
    brillo::Error::AddTo(error, FROM_HERE, http::kErrorDomain,
                         "curl_init_failed", "Failed to initialize CURL");
    return connection;
  }

  VLOG(1) << "Sending a " << method << " request to " << url;
  CURLcode code = curl_interface_->EasySetOptStr(curl_handle, CURLOPT_URL, url);

  if (code == CURLE_OK) {
    // CURLOPT_CAINFO is a string, but CurlApi::EasySetOptStr will never pass
    // curl_easy_setopt a null pointer, so we use EasySetOptPtr instead.
    code = curl_interface_->EasySetOptPtr(curl_handle, CURLOPT_CAINFO, nullptr);
  }
  if (code == CURLE_OK) {
    CHECK(base::PathExists(certificate_path_));
    code = curl_interface_->EasySetOptStr(curl_handle, CURLOPT_CAPATH,
                                          certificate_path_.value());
  }
  if (code == CURLE_OK) {
    code =
        curl_interface_->EasySetOptInt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1);
  }
  if (code == CURLE_OK) {
    code =
        curl_interface_->EasySetOptInt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2);
  }
  if (code == CURLE_OK && !user_agent.empty()) {
    code = curl_interface_->EasySetOptStr(curl_handle, CURLOPT_USERAGENT,
                                          user_agent);
  }
  if (code == CURLE_OK && !referer.empty()) {
    code =
        curl_interface_->EasySetOptStr(curl_handle, CURLOPT_REFERER, referer);
  }
  if (code == CURLE_OK && !proxy_.empty()) {
    code = curl_interface_->EasySetOptStr(curl_handle, CURLOPT_PROXY, proxy_);
  }
  if (code == CURLE_OK) {
    int64_t timeout_ms = connection_timeout_.InMillisecondsRoundedUp();

    if (timeout_ms > 0 && timeout_ms <= std::numeric_limits<int>::max()) {
      code = curl_interface_->EasySetOptInt(curl_handle, CURLOPT_TIMEOUT_MS,
                                            static_cast<int>(timeout_ms));
    }
  }
  if (code == CURLE_OK && !ip_address_.empty()) {
    code = curl_interface_->EasySetOptStr(curl_handle, CURLOPT_INTERFACE,
                                          ip_address_);
  }
  if (code == CURLE_OK && !dns_servers_.empty()) {
    code = curl_interface_->EasySetOptStr(curl_handle, CURLOPT_DNS_SERVERS,
                                          base::JoinString(dns_servers_, ","));
  }
  if (code == CURLE_OK && !dns_interface_.empty()) {
    code = curl_interface_->EasySetOptStr(curl_handle, CURLOPT_DNS_INTERFACE,
                                          dns_interface_);
  }
  if (code == CURLE_OK && !dns_ipv4_addr_.empty()) {
    code = curl_interface_->EasySetOptStr(curl_handle, CURLOPT_DNS_LOCAL_IP4,
                                          dns_ipv4_addr_);
  }
  if (code == CURLE_OK && !dns_ipv6_addr_.empty()) {
    code = curl_interface_->EasySetOptStr(curl_handle, CURLOPT_DNS_LOCAL_IP6,
                                          dns_ipv6_addr_);
  }
  if (code == CURLE_OK && host_list_) {
    code = curl_interface_->EasySetOptPtr(curl_handle, CURLOPT_RESOLVE,
                                          host_list_);
  }

  if (code == CURLE_OK && buffer_size_.has_value()) {
    code = curl_interface_->EasySetOptInt(curl_handle, CURLOPT_BUFFERSIZE,
                                          buffer_size_.value());
  }

  if (code == CURLE_OK && upload_buffer_size_.has_value()) {
    code = curl_interface_->EasySetOptInt(
        curl_handle, CURLOPT_UPLOAD_BUFFERSIZE, upload_buffer_size_.value());
  }

  // Setup HTTP request method and optional request body.
  if (code == CURLE_OK) {
    if (method == request_type::kGet) {
      code = curl_interface_->EasySetOptInt(curl_handle, CURLOPT_HTTPGET, 1);
    } else if (method == request_type::kHead) {
      code = curl_interface_->EasySetOptInt(curl_handle, CURLOPT_NOBODY, 1);
    } else if (method == request_type::kPut) {
      code = curl_interface_->EasySetOptInt(curl_handle, CURLOPT_UPLOAD, 1);
    } else {
      // POST and custom request methods
      code = curl_interface_->EasySetOptInt(curl_handle, CURLOPT_POST, 1);
      if (code == CURLE_OK) {
        code = curl_interface_->EasySetOptPtr(curl_handle, CURLOPT_POSTFIELDS,
                                              nullptr);
      }
      if (code == CURLE_OK && method != request_type::kPost) {
        code = curl_interface_->EasySetOptStr(curl_handle,
                                              CURLOPT_CUSTOMREQUEST, method);
      }
    }
  }

  if (code != CURLE_OK) {
    AddEasyCurlError(error, FROM_HERE, code, curl_interface_.get());
    curl_interface_->EasyCleanup(curl_handle);
    return connection;
  }

  connection = std::make_shared<http::curl::Connection>(
      curl_handle, method, curl_interface_, shared_from_this());
  if (!connection->SendHeaders(headers, error)) {
    connection.reset();
  }
  return connection;
}

void Transport::RunCallbackAsync(const base::Location& from_here,
                                 base::OnceClosure callback) {
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      from_here, std::move(callback));
}

RequestID Transport::StartAsyncTransfer(http::Connection* connection,
                                        SuccessCallback success_callback,
                                        ErrorCallback error_callback) {
  brillo::ErrorPtr error;
  if (!SetupAsyncCurl(&error)) {
    RunCallbackAsync(FROM_HERE, base::BindOnce(std::move(error_callback), 0,
                                               base::Owned(error.release())));
    return 0;
  }

  // Wrap the |success_callback| and |error_callback| into RepeatingCallbacks
  // to prevent crashes when they are invoked more than once accidentally.
  // This pattern should be avoided when possible since it subverts the
  // Once/Repeating paradigm. We should consider migrating them to OnceCallbcks
  // when their lifetimes are more clear.
  auto repeating_success_callback =
      AdaptOnceCallbackForRepeating(std::move(success_callback));
  auto repeating_error_callback =
      AdaptOnceCallbackForRepeating(std::move(error_callback));

  RequestID request_id = ++last_request_id_;

  auto curl_connection = static_cast<http::curl::Connection*>(connection);
  std::unique_ptr<AsyncRequestData> request_data{new AsyncRequestData};
  // Add the request data to |async_requests_| before adding the CURL handle
  // in case CURL feels like calling the socket callback synchronously which
  // will need the data to be in |async_requests_| map already.
  request_data->success_callback = repeating_success_callback;
  request_data->error_callback = repeating_error_callback;
  request_data->connection =
      std::static_pointer_cast<Connection>(curl_connection->shared_from_this());
  request_data->request_id = request_id;
  async_requests_.emplace(curl_connection, std::move(request_data));
  request_id_map_.emplace(request_id, curl_connection);

  // Add the connection's CURL handle to the multi-handle.
  CURLMcode code = curl_interface_->MultiAddHandle(
      curl_multi_handle_, curl_connection->curl_handle_);
  if (code != CURLM_OK) {
    brillo::ErrorPtr error;
    AddMultiCurlError(&error, FROM_HERE, code, curl_interface_.get());
    RunCallbackAsync(FROM_HERE, base::BindOnce(repeating_error_callback, 0,
                                               base::Owned(error.release())));
    async_requests_.erase(curl_connection);
    request_id_map_.erase(request_id);
    return 0;
  }
  VLOG(1) << "Started asynchronous HTTP request with ID " << request_id;
  return request_id;
}

bool Transport::CancelRequest(RequestID request_id) {
  auto p = request_id_map_.find(request_id);
  if (p == request_id_map_.end()) {
    // The request must have been completed already...
    // This is not necessarily an error condition, so fail gracefully.
    LOG(WARNING) << "HTTP request #" << request_id << " not found";
    return false;
  }
  LOG(INFO) << "Canceling HTTP request #" << request_id;
  CleanAsyncConnection(p->second);
  return true;
}

void Transport::SetDefaultTimeout(base::TimeDelta timeout) {
  connection_timeout_ = timeout;
}

void Transport::SetLocalIpAddress(const std::string& ip_address) {
  ip_address_ = "host!" + ip_address;
}

void Transport::SetDnsServers(const std::vector<std::string>& dns_servers) {
  dns_servers_ = dns_servers;
}

void Transport::SetDnsInterface(const std::string& dns_interface) {
  dns_interface_ = dns_interface;
}

void Transport::SetDnsLocalIPv4Address(const std::string& dns_ipv4_addr) {
  dns_ipv4_addr_ = dns_ipv4_addr;
}

void Transport::SetDnsLocalIPv6Address(const std::string& dns_ipv6_addr) {
  dns_ipv6_addr_ = dns_ipv6_addr;
}

void Transport::UseDefaultCertificate() {
  UseCustomCertificate(Certificate::kDefault);
}

void Transport::UseCustomCertificate(Transport::Certificate cert) {
  certificate_path_ = CertificateToPath(cert);
  CHECK(base::PathExists(certificate_path_));
}

void Transport::ResolveHostToIp(const std::string& host,
                                uint16_t port,
                                const std::string& ip_address) {
  host_list_ = curl_slist_append(
      host_list_,
      base::StringPrintf("%s:%d:%s", host.c_str(), port, ip_address.c_str())
          .c_str());
}

void Transport::SetBufferSize(std::optional<int> buffer_size) {
  buffer_size_ = buffer_size;
}

void Transport::SetUploadBufferSize(std::optional<int> buffer_size) {
  upload_buffer_size_ = buffer_size;
}

void Transport::ClearHost() {
  curl_slist_free_all(host_list_);
  host_list_ = nullptr;
}

void Transport::AddEasyCurlError(brillo::ErrorPtr* error,
                                 const base::Location& location,
                                 CURLcode code,
                                 CurlInterface* curl_interface) {
  brillo::Error::AddTo(error, location, "curl_easy_error",
                       brillo::string_utils::ToString(code),
                       curl_interface->EasyStrError(code));
}

void Transport::AddMultiCurlError(brillo::ErrorPtr* error,
                                  const base::Location& location,
                                  CURLMcode code,
                                  CurlInterface* curl_interface) {
  brillo::Error::AddTo(error, location, "curl_multi_error",
                       brillo::string_utils::ToString(code),
                       curl_interface->MultiStrError(code));
}

bool Transport::SetupAsyncCurl(brillo::ErrorPtr* error) {
  if (curl_multi_handle_)
    return true;

  curl_multi_handle_ = curl_interface_->MultiInit();
  if (!curl_multi_handle_) {
    LOG(ERROR) << "Failed to initialize CURL";
    brillo::Error::AddTo(error, FROM_HERE, http::kErrorDomain,
                         "curl_init_failed", "Failed to initialize CURL");
    return false;
  }

  CURLMcode code = curl_interface_->MultiSetSocketCallback(
      curl_multi_handle_, &Transport::MultiSocketCallback, this);
  if (code == CURLM_OK) {
    code = curl_interface_->MultiSetTimerCallback(
        curl_multi_handle_, &Transport::MultiTimerCallback, this);
  }
  if (code != CURLM_OK) {
    AddMultiCurlError(error, FROM_HERE, code, curl_interface_.get());
    return false;
  }
  return true;
}

void Transport::ShutDownAsyncCurl() {
  if (!curl_multi_handle_)
    return;
  LOG_IF(WARNING, !poll_data_map_.empty())
      << "There are pending requests at the time of transport's shutdown";
  // Make sure we are not leaking any memory here.
  for (const auto& pair : poll_data_map_)
    delete pair.second;
  poll_data_map_.clear();
  curl_interface_->MultiCleanup(curl_multi_handle_);
  curl_multi_handle_ = nullptr;
}

int Transport::MultiSocketCallback(
    CURL* easy, curl_socket_t s, int what, void* userp, void* socketp) {
  auto transport = static_cast<Transport*>(userp);
  CHECK(transport) << "Transport must be set for this callback";
  auto poll_data = static_cast<SocketPollData*>(socketp);
  if (!poll_data) {
    // We haven't attached polling data to this socket yet. Let's do this now.
    poll_data = new SocketPollData{transport->curl_interface_,
                                   transport->curl_multi_handle_, transport, s};
    transport->poll_data_map_.emplace(std::make_pair(easy, s), poll_data);
    transport->curl_interface_->MultiAssign(transport->curl_multi_handle_, s,
                                            poll_data);
  }

  if (what == CURL_POLL_NONE) {
    return 0;
  } else if (what == CURL_POLL_REMOVE) {
    // Remove the attached data from the socket.
    transport->curl_interface_->MultiAssign(transport->curl_multi_handle_, s,
                                            nullptr);
    transport->poll_data_map_.erase(std::make_pair(easy, s));

    // Make sure we stop watching the socket file descriptor now, before
    // we schedule the SocketPollData for deletion.
    poll_data->StopWatcher();
    // This method can be called indirectly from SocketPollData::OnSocketReady,
    // so delay destruction of SocketPollData object till the next loop cycle.
    base::SingleThreadTaskRunner::GetCurrentDefault()->DeleteSoon(FROM_HERE,
                                                                  poll_data);
    return 0;
  }

  poll_data->StopWatcher();

  bool success = true;
  if (what == CURL_POLL_IN || what == CURL_POLL_INOUT)
    success = poll_data->WatchReadable() && success;
  if (what == CURL_POLL_OUT || what == CURL_POLL_INOUT)
    success = poll_data->WatchWritable() && success;

  CHECK(success) << "Failed to watch the CURL socket.";
  return 0;
}

// CURL actually uses "long" types in callback signatures, so we must comply.
int Transport::MultiTimerCallback(CURLM* /* multi */,
                                  long timeout_ms,  // NOLINT(runtime/int)
                                  void* userp) {
  auto transport = static_cast<Transport*>(userp);
  // Cancel any previous timer callbacks.
  transport->weak_ptr_factory_for_timer_.InvalidateWeakPtrs();
  if (timeout_ms >= 0) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Transport::OnTimer,
                       transport->weak_ptr_factory_for_timer_.GetWeakPtr()),
        base::Milliseconds(timeout_ms));
  }
  return 0;
}

void Transport::OnTimer() {
  if (curl_multi_handle_) {
    int still_running_count = 0;
    curl_interface_->MultiSocketAction(curl_multi_handle_, CURL_SOCKET_TIMEOUT,
                                       0, &still_running_count);
    ProcessAsyncCurlMessages();
  }
}

void Transport::ProcessAsyncCurlMessages() {
  CURLMsg* msg = nullptr;
  int msgs_left = 0;
  while (
      (msg = curl_interface_->MultiInfoRead(curl_multi_handle_, &msgs_left))) {
    if (msg->msg == CURLMSG_DONE) {
      // Async I/O complete for a connection. Invoke the user callbacks.
      Connection* connection = nullptr;
      CHECK_EQ(CURLE_OK, curl_interface_->EasyGetInfoPtr(
                             msg->easy_handle, CURLINFO_PRIVATE,
                             reinterpret_cast<void**>(&connection)));
      CHECK(connection != nullptr);
      OnTransferComplete(connection, msg->data.result);
    }
  }
}

void Transport::OnTransferComplete(Connection* connection, CURLcode code) {
  auto p = async_requests_.find(connection);
  CHECK(p != async_requests_.end()) << "Unknown connection";
  AsyncRequestData* request_data = p->second.get();
  VLOG(1) << "HTTP request # " << request_data->request_id << " has completed "
          << (code == CURLE_OK ? "successfully" : "with an error");
  if (code != CURLE_OK) {
    brillo::ErrorPtr error;
    AddEasyCurlError(&error, FROM_HERE, code, curl_interface_.get());
    RunCallbackAsync(FROM_HERE, base::BindOnce(request_data->error_callback,
                                               p->second->request_id,
                                               base::Owned(error.release())));
  } else {
    if (connection->GetResponseStatusCode() != status_code::Ok) {
      LOG(INFO) << "Response: " << connection->GetResponseStatusCode() << " ("
                << connection->GetResponseStatusText() << ")";
    }
    brillo::ErrorPtr error;
    // Rewind the response data stream to the beginning so the clients can
    // read the data back.
    const auto& stream = request_data->connection->response_data_stream_;
    if (stream && stream->CanSeek() && !stream->SetPosition(0, &error)) {
      RunCallbackAsync(FROM_HERE, base::BindOnce(request_data->error_callback,
                                                 p->second->request_id,
                                                 base::Owned(error.release())));
    } else {
      std::unique_ptr<Response> resp{new Response{request_data->connection}};
      RunCallbackAsync(FROM_HERE,
                       base::BindOnce(request_data->success_callback,
                                      p->second->request_id, std::move(resp)));
    }
  }
  // In case of an error on CURL side, we would have dispatched the error
  // callback and we need to clean up the current connection, however the
  // error callback has no reference to the connection itself and
  // |async_requests_| is the only reference to the shared pointer that
  // maintains the lifetime of |connection| and possibly even this Transport
  // object instance. As a result, if we call CleanAsyncConnection() directly,
  // there is a chance that this object might be deleted.
  // Instead, schedule an asynchronous task to clean up the connection.
  RunCallbackAsync(FROM_HERE,
                   base::BindOnce(&Transport::CleanAsyncConnection,
                                  weak_ptr_factory_.GetWeakPtr(), connection));
}

void Transport::CleanAsyncConnection(Connection* connection) {
  auto p = async_requests_.find(connection);
  CHECK(p != async_requests_.end()) << "Unknown connection";
  // Remove the request data from the map first, since this might be the only
  // reference to the Connection class and even possibly to this Transport.
  auto request_data = std::move(p->second);

  // Remove associated request ID.
  request_id_map_.erase(request_data->request_id);

  // Remove the connection's CURL handle from multi-handle.
  curl_interface_->MultiRemoveHandle(curl_multi_handle_,
                                     connection->curl_handle_);

  // Remove all the socket data associated with this connection.
  auto iter = poll_data_map_.begin();
  while (iter != poll_data_map_.end()) {
    if (iter->first.first == connection->curl_handle_)
      iter = poll_data_map_.erase(iter);
    else
      ++iter;
  }
  // Remove pending asynchronous request data.
  // This must be last since there is a chance of this object being
  // destroyed as the result. See the comment in Transport::OnTransferComplete.
  async_requests_.erase(p);
}

}  // namespace curl
}  // namespace http
}  // namespace brillo
