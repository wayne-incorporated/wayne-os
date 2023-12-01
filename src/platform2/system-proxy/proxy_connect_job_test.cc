// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "system-proxy/proxy_connect_job.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <utility>

#include <curl/curl.h>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_executor.h>
#include <base/test/test_mock_time_task_runner.h>
#include <brillo/message_loops/base_message_loop.h>
#include <chromeos/patchpanel/net_util.h>
#include <chromeos/patchpanel/socket.h>
#include <chromeos/patchpanel/socket_forwarder.h>

#include "bindings/worker_common.pb.h"
#include "system-proxy/protobuf_util.h"
#include "system-proxy/test_http_server.h"

namespace {

constexpr char kCredentials[] = "username:pwd";
constexpr char kValidConnectRequest[] =
    "CONNECT www.example.server.com:443 HTTP/1.1\r\n\r\n";
constexpr char kProxyAuthorizationHeaderToken[] = "Proxy-Authorization:";
}  // namespace

namespace system_proxy {

using ::testing::_;
using ::testing::Return;

class ProxyConnectJobTest : public ::testing::Test {
 public:
  struct HttpAuthEntry {
    HttpAuthEntry(const std::string& origin,
                  const std::string& scheme,
                  const std::string& realm,
                  const std::string& credentials)
        : origin(origin),
          scheme(scheme),
          realm(realm),
          credentials(credentials) {}
    std::string origin;
    std::string scheme;
    std::string realm;
    std::string credentials;
  };
  ProxyConnectJobTest() = default;
  ProxyConnectJobTest(const ProxyConnectJobTest&) = delete;
  ProxyConnectJobTest& operator=(const ProxyConnectJobTest&) = delete;
  ~ProxyConnectJobTest() = default;

  void SetUp() override {
    int fds[2];
    ASSERT_NE(-1,
              socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                         0 /* protocol */, fds));
    cros_client_socket_ =
        std::make_unique<patchpanel::Socket>(base::ScopedFD(fds[1]));

    connect_job_ = std::make_unique<ProxyConnectJob>(
        std::make_unique<patchpanel::Socket>(base::ScopedFD(fds[0])), "",
        CURLAUTH_ANY,
        base::BindOnce(&ProxyConnectJobTest::ResolveProxy,
                       base::Unretained(this)),
        base::BindRepeating(&ProxyConnectJobTest::OnAuthCredentialsRequired,
                            base::Unretained(this)),
        base::BindOnce(&ProxyConnectJobTest::OnConnectionSetupFinished,
                       base::Unretained(this)));
  }

 protected:
  virtual void OnConnectionSetupFinished(
      std::unique_ptr<patchpanel::SocketForwarder> fwd,
      ProxyConnectJob* connect_job) {}
  virtual void ResolveProxy(
      const std::string& target_url,
      base::OnceCallback<void(const std::list<std::string>&)> callback) {
    std::move(callback).Run({});
  }
  virtual void OnAuthCredentialsRequired(
      const std::string& proxy_url,
      const std::string& scheme,
      const std::string& realm,
      const std::string& bad_credentials,
      base::RepeatingCallback<void(const std::string&)> callback) {
    std::move(callback).Run(/* credentials = */ "");
  }

  std::unique_ptr<ProxyConnectJob> connect_job_;
  base::SingleThreadTaskExecutor task_executor_{base::MessagePumpType::IO};
  std::unique_ptr<brillo::BaseMessageLoop> brillo_loop_{
      std::make_unique<brillo::BaseMessageLoop>(task_executor_.task_runner())};
  std::unique_ptr<patchpanel::Socket> cros_client_socket_;

  FRIEND_TEST(ProxyConnectJobTest, ClientConnectTimeoutJobCanceled);
};

TEST_F(ProxyConnectJobTest, BadHttpRequestWrongMethod) {
  connect_job_->Start();
  char badConnRequest[] = "GET www.example.server.com:443 HTTP/1.1\r\n\r\n";
  cros_client_socket_->SendTo(badConnRequest, std::strlen(badConnRequest));
  brillo_loop_->RunOnce(false);

  EXPECT_EQ("", connect_job_->target_url_);
  EXPECT_EQ(0, connect_job_->proxy_servers_.size());
  const std::string expected_http_response =
      "HTTP/1.1 400 Bad Request - Origin: local proxy\r\n\r\n";
  std::vector<char> buf(expected_http_response.size());
  ASSERT_TRUE(
      base::ReadFromFD(cros_client_socket_->fd(), buf.data(), buf.size()));
  std::string actual_response(buf.data(), buf.size());
  EXPECT_EQ(expected_http_response, actual_response);
}

TEST_F(ProxyConnectJobTest, SlowlorisTimeout) {
  // Add a TaskRunner where we can control time.
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner{
      new base::TestMockTimeTaskRunner()};
  brillo_loop_ = nullptr;
  brillo_loop_ = std::make_unique<brillo::BaseMessageLoop>(task_runner);
  base::TestMockTimeTaskRunner::ScopedContext scoped_context(task_runner.get());

  connect_job_->Start();
  // No empty line after http message.
  char badConnRequest[] = "CONNECT www.example.server.com:443 HTTP/1.1\r\n";
  cros_client_socket_->SendTo(badConnRequest, std::strlen(badConnRequest));
  task_runner->RunUntilIdle();

  EXPECT_EQ(1, task_runner->GetPendingTaskCount());
  constexpr base::TimeDelta kDoubleWaitClientConnectTimeout = base::Seconds(4);
  // Move the time ahead so that the client connection timeout callback is
  // triggered.
  task_runner->FastForwardBy(kDoubleWaitClientConnectTimeout);

  EXPECT_EQ("", connect_job_->target_url_);
  EXPECT_EQ(0, connect_job_->proxy_servers_.size());
  const std::string expected_http_response =
      "HTTP/1.1 408 Request Timeout - Origin: local proxy\r\n\r\n";
  std::vector<char> buf(expected_http_response.size());
  ASSERT_TRUE(
      base::ReadFromFD(cros_client_socket_->fd(), buf.data(), buf.size()));
  std::string actual_response(buf.data(), buf.size());
  EXPECT_EQ(expected_http_response, actual_response);
}

TEST_F(ProxyConnectJobTest, WaitClientConnectTimeout) {
  // Add a TaskRunner where we can control time.
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner{
      new base::TestMockTimeTaskRunner()};
  brillo_loop_ = nullptr;
  brillo_loop_ = std::make_unique<brillo::BaseMessageLoop>(task_runner);
  base::TestMockTimeTaskRunner::ScopedContext scoped_context(task_runner.get());

  connect_job_->Start();

  EXPECT_EQ(1, task_runner->GetPendingTaskCount());
  // Move the time ahead so that the client connection timeout callback is
  // triggered.
  task_runner->FastForwardBy(task_runner->NextPendingTaskDelay());

  const std::string expected_http_response =
      "HTTP/1.1 408 Request Timeout - Origin: local proxy\r\n\r\n";
  std::vector<char> buf(expected_http_response.size());
  ASSERT_TRUE(
      base::ReadFromFD(cros_client_socket_->fd(), buf.data(), buf.size()));
  std::string actual_response(buf.data(), buf.size());

  EXPECT_EQ(expected_http_response, actual_response);
}

// Check that the client connect timeout callback is not fired if the owning
// proxy connect job is destroyed.
TEST_F(ProxyConnectJobTest, ClientConnectTimeoutJobCanceled) {
  // Add a TaskRunner where we can control time.
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner{
      new base::TestMockTimeTaskRunner()};
  brillo_loop_ = nullptr;
  brillo_loop_ = std::make_unique<brillo::BaseMessageLoop>(task_runner);
  base::TestMockTimeTaskRunner::ScopedContext scoped_context(task_runner.get());

  // Create a proxy connect job and start the client connect timeout counter.
  {
    int fds[2];
    ASSERT_NE(-1,
              socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                         0 /* protocol */, fds));
    auto client_socket =
        std::make_unique<patchpanel::Socket>(base::ScopedFD(fds[1]));

    auto connect_job = std::make_unique<ProxyConnectJob>(
        std::make_unique<patchpanel::Socket>(base::ScopedFD(fds[0])), "",
        CURLAUTH_ANY,
        base::BindOnce(&ProxyConnectJobTest::ResolveProxy,
                       base::Unretained(this)),
        base::BindRepeating(&ProxyConnectJobTest::OnAuthCredentialsRequired,
                            base::Unretained(this)),
        base::BindOnce(&ProxyConnectJobTest::OnConnectionSetupFinished,
                       base::Unretained(this)));
    // Post the timeout task.
    connect_job->Start();
    EXPECT_TRUE(task_runner->HasPendingTask());
  }
  // Check that the task was canceled.
  EXPECT_FALSE(task_runner->HasPendingTask());
}

class HttpServerProxyConnectJobTest : public ProxyConnectJobTest {
 public:
  HttpServerProxyConnectJobTest() = default;
  HttpServerProxyConnectJobTest(const HttpServerProxyConnectJobTest&) = delete;
  HttpServerProxyConnectJobTest& operator=(
      const HttpServerProxyConnectJobTest&) = delete;
  ~HttpServerProxyConnectJobTest() = default;

 protected:
  HttpTestServer http_test_server_;

  std::vector<HttpAuthEntry> http_auth_cache_;
  bool auth_requested_ = false;

  void AddHttpAuthEntry(const std::string& origin,
                        const std::string& scheme,
                        const std::string& realm,
                        const std::string& credentials) {
    http_auth_cache_.push_back(
        HttpAuthEntry(origin, scheme, realm, credentials));
  }

  bool AuthRequested() { return auth_requested_; }

  void AddServerReply(HttpTestServer::HttpConnectReply reply) {
    http_test_server_.AddHttpConnectReply(reply);
  }

  void ResolveProxy(const std::string& target_url,
                    base::OnceCallback<void(const std::list<std::string>&)>
                        callback) override {
    // Return the URL of the test proxy.
    std::move(callback).Run({http_test_server_.GetUrl()});
  }

  void OnAuthCredentialsRequired(
      const std::string& proxy_url,
      const std::string& scheme,
      const std::string& realm,
      const std::string& bad_credentials,
      base::RepeatingCallback<void(const std::string&)> callback) override {
    auth_requested_ = true;
    for (const auto& auth_entry : http_auth_cache_) {
      if (auth_entry.origin == proxy_url && auth_entry.realm == realm &&
          auth_entry.scheme == scheme) {
        std::move(callback).Run(auth_entry.credentials);
        return;
      }
    }
    if (invoke_authentication_callback_) {
      std::move(callback).Run(/* credentials = */ "");
    }
  }
  void OnConnectionSetupFinished(
      std::unique_ptr<patchpanel::SocketForwarder> fwd,
      ProxyConnectJob* connect_job) override {
    ASSERT_EQ(connect_job, connect_job_.get());
    if (fwd) {
      forwarder_created_ = true;

      brillo_loop_->RunOnce(false);

      fwd.reset();
    }
  }

  bool forwarder_created_ = false;
  // Used to simulate time-outs while waiting for credentials from the Browser.
  bool invoke_authentication_callback_ = true;
};

TEST_F(HttpServerProxyConnectJobTest, SuccessfulConnection) {
  AddServerReply(HttpTestServer::HttpConnectReply::kOk);
  http_test_server_.Start();

  connect_job_->Start();
  cros_client_socket_->SendTo(kValidConnectRequest,
                              std::strlen(kValidConnectRequest));
  brillo_loop_->RunOnce(false);
  EXPECT_EQ("www.example.server.com:443", connect_job_->target_url_);
  EXPECT_EQ(1, connect_job_->proxy_servers_.size());
  EXPECT_EQ(http_test_server_.GetUrl(), connect_job_->proxy_servers_.front());
  EXPECT_TRUE(forwarder_created_);
}

TEST_F(HttpServerProxyConnectJobTest, MultipleReadConnectRequest) {
  AddServerReply(HttpTestServer::HttpConnectReply::kOk);
  http_test_server_.Start();
  connect_job_->Start();
  char part1[] = "CONNECT www.example.server.com:443 HTTP/1.1\r\n";
  char part2[] = "\r\n";
  cros_client_socket_->SendTo(part1, std::strlen(part1));
  // Process the partial CONNECT request.
  brillo_loop_->RunOnce(false);
  cros_client_socket_->SendTo(part2, std::strlen(part2));
  brillo_loop_->RunOnce(false);
  EXPECT_EQ("www.example.server.com:443", connect_job_->target_url_);
  EXPECT_EQ(1, connect_job_->proxy_servers_.size());
  EXPECT_EQ(http_test_server_.GetUrl(), connect_job_->proxy_servers_.front());
  EXPECT_TRUE(forwarder_created_);
}

TEST_F(HttpServerProxyConnectJobTest, TunnelFailedBadGatewayFromRemote) {
  AddServerReply(HttpTestServer::HttpConnectReply::kBadGateway);
  http_test_server_.Start();

  connect_job_->Start();
  cros_client_socket_->SendTo(kValidConnectRequest,
                              std::strlen(kValidConnectRequest));
  brillo_loop_->RunOnce(false);
  EXPECT_FALSE(forwarder_created_);

  std::string expected_server_reply =
      "HTTP/1.1 502 Error creating tunnel - Origin: local proxy\r\n\r\n";
  std::vector<char> buf(expected_server_reply.size());

  ASSERT_TRUE(cros_client_socket_->RecvFrom(buf.data(), buf.size()));
  std::string actual_server_reply(buf.data(), buf.size());
  EXPECT_EQ(expected_server_reply, actual_server_reply);
}

TEST_F(HttpServerProxyConnectJobTest, SuccessfulConnectionAltEnding) {
  AddServerReply(HttpTestServer::HttpConnectReply::kOk);
  http_test_server_.Start();

  connect_job_->Start();
  char validConnRequest[] = "CONNECT www.example.server.com:443 HTTP/1.1\r\n\n";
  cros_client_socket_->SendTo(validConnRequest, std::strlen(validConnRequest));
  brillo_loop_->RunOnce(false);

  EXPECT_EQ("www.example.server.com:443", connect_job_->target_url_);
  EXPECT_EQ(1, connect_job_->proxy_servers_.size());
  EXPECT_EQ(http_test_server_.GetUrl(), connect_job_->proxy_servers_.front());
  EXPECT_TRUE(forwarder_created_);
  ASSERT_FALSE(AuthRequested());
}

// Test that the the CONNECT request is sent again after acquiring credentials.
TEST_F(HttpServerProxyConnectJobTest, ResendWithCredentials) {
  AddServerReply(HttpTestServer::HttpConnectReply::kAuthRequiredBasic);
  AddServerReply(HttpTestServer::HttpConnectReply::kOk);
  http_test_server_.Start();

  AddHttpAuthEntry(http_test_server_.GetUrl(), "Basic", "\"My Proxy\"",
                   kCredentials);
  connect_job_->Start();

  cros_client_socket_->SendTo(kValidConnectRequest,
                              std::strlen(kValidConnectRequest));
  brillo_loop_->RunOnce(false);

  ASSERT_TRUE(AuthRequested());
  EXPECT_TRUE(forwarder_created_);
  EXPECT_EQ(kCredentials, connect_job_->credentials_);
  EXPECT_EQ(200, connect_job_->http_response_code_);
}

// Test that the proxy auth required status is forwarded to the client if
// credentials are missing.
TEST_F(HttpServerProxyConnectJobTest, NoCredentials) {
  AddServerReply(HttpTestServer::HttpConnectReply::kAuthRequiredBasic);
  http_test_server_.Start();
  connect_job_->Start();

  cros_client_socket_->SendTo(kValidConnectRequest,
                              std::strlen(kValidConnectRequest));
  brillo_loop_->RunOnce(false);

  ASSERT_TRUE(AuthRequested());
  EXPECT_EQ("", connect_job_->credentials_);
  EXPECT_EQ(407, connect_job_->http_response_code_);
}

// Test that the proxy auth required status is forwarded to the client if the
// server chose Kerberos as an authentication method.
TEST_F(HttpServerProxyConnectJobTest, KerberosAuth) {
  AddServerReply(HttpTestServer::HttpConnectReply::kAuthRequiredKerberos);
  http_test_server_.Start();

  connect_job_->Start();

  cros_client_socket_->SendTo(kValidConnectRequest,
                              std::strlen(kValidConnectRequest));
  brillo_loop_->RunOnce(false);

  ASSERT_FALSE(AuthRequested());
  EXPECT_EQ("", connect_job_->credentials_);
  EXPECT_EQ(407, connect_job_->http_response_code_);
}

// Test that the connection times out while waiting for credentials from the
// Browser.
TEST_F(HttpServerProxyConnectJobTest, AuthenticationTimeout) {
  // Add a TaskRunner where we can control time.
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner{
      new base::TestMockTimeTaskRunner()};
  brillo_loop_ = nullptr;
  brillo_loop_ = std::make_unique<brillo::BaseMessageLoop>(task_runner);
  base::TestMockTimeTaskRunner::ScopedContext scoped_context(task_runner.get());

  invoke_authentication_callback_ = false;

  AddServerReply(HttpTestServer::HttpConnectReply::kAuthRequiredBasic);
  http_test_server_.Start();

  connect_job_->Start();

  cros_client_socket_->SendTo(kValidConnectRequest,
                              std::strlen(kValidConnectRequest));
  task_runner->RunUntilIdle();
  // We need to manually invoke the method which reads from the client socket
  // because |task_runner| will not execute the FileDescriptorWatcher's tasks.
  connect_job_->OnClientReadReady();

  // Check that an authentication request was sent.
  ASSERT_TRUE(AuthRequested());
  EXPECT_EQ(1, task_runner->GetPendingTaskCount());
  // Move the time ahead so that the client connection timeout callback is
  // triggered.
  task_runner->FastForwardBy(task_runner->NextPendingTaskDelay());

  const std::string expected_http_response =
      "HTTP/1.1 407 Credentials required - Origin: local proxy\r\n\r\n";
  std::vector<char> buf(expected_http_response.size());
  ASSERT_TRUE(
      base::ReadFromFD(cros_client_socket_->fd(), buf.data(), buf.size()));
  std::string actual_response(buf.data(), buf.size());

  // Check that the auth failure was forwarded to the client.
  EXPECT_EQ(expected_http_response, actual_response);
}

// Verifies that the receiving the same bad credentials twice will send an auth
// failure to the Chrome OS local client.
TEST_F(HttpServerProxyConnectJobTest, CancelIfBadCredentials) {
  AddServerReply(HttpTestServer::HttpConnectReply::kAuthRequiredBasic);
  AddServerReply(HttpTestServer::HttpConnectReply::kAuthRequiredBasic);
  http_test_server_.Start();

  AddHttpAuthEntry(http_test_server_.GetUrl(), "Basic", "\"My Proxy\"",
                   kCredentials);

  connect_job_->Start();

  cros_client_socket_->SendTo(kValidConnectRequest,
                              std::strlen(kValidConnectRequest));
  brillo_loop_->RunOnce(false);

  ASSERT_TRUE(AuthRequested());

  const std::string expected_http_response =
      "HTTP/1.1 407 Credentials required - Origin: local proxy\r\n\r\n";
  std::vector<char> buf(expected_http_response.size());
  ASSERT_TRUE(
      base::ReadFromFD(cros_client_socket_->fd(), buf.data(), buf.size()));
  std::string actual_response(buf.data(), buf.size());

  EXPECT_EQ(expected_http_response, actual_response);
}

//  This test verifies that any data sent by a client immediately after the end
//  of the HTTP CONNECT request is cached correctly.
TEST_F(HttpServerProxyConnectJobTest, BufferedClientData) {
  char connectRequestwithData[] =
      "CONNECT www.example.server.com:443 HTTP/1.1\r\n\r\nTest body";
  AddServerReply(HttpTestServer::HttpConnectReply::kAuthRequiredBasic);
  AddServerReply(HttpTestServer::HttpConnectReply::kOk);
  http_test_server_.Start();

  AddHttpAuthEntry(http_test_server_.GetUrl(), "Basic", "\"My Proxy\"",
                   kCredentials);
  connect_job_->Start();

  cros_client_socket_->SendTo(connectRequestwithData,
                              std::strlen(connectRequestwithData));
  brillo_loop_->RunOnce(false);

  const std::string expected = "Test body";
  const std::string actual(connect_job_->connect_data_.data(),
                           connect_job_->connect_data_.size());
}

TEST_F(HttpServerProxyConnectJobTest, BufferedClientDataAltEnding) {
  char connectRequestwithData[] =
      "CONNECT www.example.server.com:443 HTTP/1.1\r\n\nTest body";
  AddServerReply(HttpTestServer::HttpConnectReply::kAuthRequiredBasic);
  AddServerReply(HttpTestServer::HttpConnectReply::kOk);
  http_test_server_.Start();

  AddHttpAuthEntry(http_test_server_.GetUrl(), "Basic", "\"My Proxy\"",
                   kCredentials);
  connect_job_->Start();

  cros_client_socket_->SendTo(connectRequestwithData,
                              std::strlen(connectRequestwithData));
  brillo_loop_->RunOnce(false);

  const std::string expected = "Test body";
  const std::string actual(connect_job_->connect_data_.data(),
                           connect_job_->connect_data_.size());
}

// Test that the policy auth scheme is respected by curl.
TEST_F(HttpServerProxyConnectJobTest, PolicyAuthSchemeOk) {
  AddServerReply(HttpTestServer::HttpConnectReply::kAuthRequiredBasic);
  http_test_server_.Start();
  connect_job_->credentials_ = "a:b";
  connect_job_->curl_auth_schemes_ = CURLAUTH_BASIC;
  connect_job_->StoreRequestHeadersForTesting();
  connect_job_->Start();

  cros_client_socket_->SendTo(kValidConnectRequest,
                              std::strlen(kValidConnectRequest));
  brillo_loop_->RunOnce(false);

  std::size_t pos = connect_job_->GetRequestHeadersForTesting().find(
      kProxyAuthorizationHeaderToken);
  // Expect to find the proxy auth headers since CURLAUTH_BASIC is an allowed
  // auth scheme.
  EXPECT_NE(pos, std::string::npos);
}

// Test that proxy auth headers with credentials are not sent by curl if the
// auth scheme used by the server is not allowed.
TEST_F(HttpServerProxyConnectJobTest, PolicyAuthBadScheme) {
  AddServerReply(HttpTestServer::HttpConnectReply::kAuthRequiredBasic);
  http_test_server_.Start();
  connect_job_->credentials_ = "a:b";
  connect_job_->curl_auth_schemes_ = CURLAUTH_DIGEST;
  connect_job_->StoreRequestHeadersForTesting();
  connect_job_->Start();

  cros_client_socket_->SendTo(kValidConnectRequest,
                              std::strlen(kValidConnectRequest));
  brillo_loop_->RunOnce(false);

  std::size_t pos = connect_job_->GetRequestHeadersForTesting().find(
      kProxyAuthorizationHeaderToken);
  // Expect not to find the proxy auth headers since CURLAUTH_BASIC is not an
  // allowed auth scheme.
  EXPECT_EQ(pos, std::string::npos);
}

}  // namespace system_proxy
