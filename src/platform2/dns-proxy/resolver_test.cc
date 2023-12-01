// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dns-proxy/resolver.h"

#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dns-proxy/ares_client.h"
#include "dns-proxy/doh_curl_client.h"

using testing::_;
using testing::ElementsAre;
using testing::ElementsAreArray;
using testing::Return;
using testing::UnorderedElementsAreArray;

namespace dns_proxy {
namespace {
const std::vector<std::string> kTestNameServers{"8.8.8.8", "8.8.4.4"};
const std::vector<std::string> kTestDoHProviders{
    "https://dns.google/dns-query", "https://dns2.google/dns-query"};
constexpr base::TimeDelta kTimeout = base::Seconds(3);

class MockDoHCurlClient : public DoHCurlClient {
 public:
  MockDoHCurlClient() : DoHCurlClient(kTimeout) {}
  ~MockDoHCurlClient() = default;

  MOCK_METHOD5(Resolve,
               bool(const char* msg,
                    int len,
                    const QueryCallback& callback,
                    const std::vector<std::string>&,
                    const std::string&));
};

class MockAresClient : public AresClient {
 public:
  MockAresClient() : AresClient(kTimeout) {}
  ~MockAresClient() = default;

  MOCK_METHOD5(Resolve,
               bool(const unsigned char* msg,
                    size_t len,
                    const QueryCallback& callback,
                    const std::string& name_server,
                    int type));
};

}  // namespace

class ResolverTest : public testing::Test {
 public:
  void SetNameServers(const std::vector<std::string>& name_servers,
                      bool validate = false) {
    resolver_->SetNameServers(name_servers);
    if (!validate) {
      return;
    }
    // Validate name servers.
    for (const auto& name_server : name_servers) {
      auto probe_state =
          std::make_unique<Resolver::ProbeState>(name_server, /*doh=*/false);
      resolver_->HandleDo53ProbeResult(probe_state->weak_factory.GetWeakPtr(),
                                       {}, ARES_SUCCESS, nullptr, 0);
    }
  }

  void SetDoHProviders(const std::vector<std::string>& doh_providers,
                       bool validate = false,
                       bool always_on_doh = false) {
    resolver_->SetDoHProviders(doh_providers, always_on_doh);
    if (!validate) {
      return;
    }
    // Validate DoH providers.
    for (const auto& doh_provider : doh_providers) {
      DoHCurlClient::CurlResult res(CURLE_OK, 200 /* http_code */,
                                    0 /* timeout */);
      auto probe_state =
          std::make_unique<Resolver::ProbeState>(doh_provider, /*doh=*/true);
      resolver_->HandleDoHProbeResult(probe_state->weak_factory.GetWeakPtr(),
                                      {}, res, nullptr, 0);
    }
  }

 protected:
  void SetUp() override {
    std::unique_ptr<MockAresClient> scoped_ares_client(new MockAresClient());
    std::unique_ptr<MockDoHCurlClient> scoped_curl_client(
        new MockDoHCurlClient());
    ares_client_ = scoped_ares_client.get();
    curl_client_ = scoped_curl_client.get();
    resolver_ = std::make_unique<Resolver>(std::move(scoped_ares_client),
                                           std::move(scoped_curl_client));
  }

  base::test::TaskEnvironment task_environment_;

  MockAresClient* ares_client_;
  MockDoHCurlClient* curl_client_;
  std::unique_ptr<Resolver> resolver_;
};

TEST_F(ResolverTest, SetNameServers) {
  for (const auto& name_server : kTestNameServers) {
    EXPECT_CALL(*ares_client_, Resolve(_, _, _, name_server, _))
        .WillOnce(Return(true));
  }

  SetNameServers(kTestNameServers, /*validate=*/true);

  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);
}

TEST_F(ResolverTest, SetDoHProviders) {
  for (const auto& doh_provider : kTestDoHProviders) {
    EXPECT_CALL(*curl_client_,
                Resolve(_, _, _, UnorderedElementsAreArray(kTestNameServers),
                        doh_provider))
        .WillOnce(Return(true));
  }

  SetNameServers(kTestNameServers, /*validate=*/true);
  SetDoHProviders(kTestDoHProviders, /*validate=*/true, /*always_on_doh=*/true);

  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);
}

TEST_F(ResolverTest, Resolve_DNSDoHServersNotValidated) {
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _))
      .Times(kTestNameServers.size())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  SetNameServers(kTestNameServers);
  SetDoHProviders(kTestDoHProviders);

  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);
}

TEST_F(ResolverTest, Resolve_DNSDoHServersPartiallyValidated) {
  SetNameServers(kTestNameServers);
  SetDoHProviders(kTestDoHProviders);

  const auto& validated_doh_provider = kTestDoHProviders.front();
  DoHCurlClient::CurlResult res(CURLE_OK, 200 /* http_code */, 0 /* timeout*/);
  auto probe_state = std::make_unique<Resolver::ProbeState>(
      validated_doh_provider, /*doh=*/true);
  resolver_->HandleDoHProbeResult(probe_state->weak_factory.GetWeakPtr(), {},
                                  res, nullptr, 0);

  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, validated_doh_provider))
      .WillOnce(Return(true));

  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);
}

TEST_F(ResolverTest, Resolve_DNSDoHServersValidated) {
  SetNameServers(kTestNameServers, /*validate=*/true);
  SetDoHProviders(kTestDoHProviders, /*validate=*/true);

  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _))
      .Times(kTestDoHProviders.size())
      .WillRepeatedly(Return(true));

  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);
}

TEST_F(ResolverTest, Resolve_DNSServers) {
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _))
      .Times(kTestNameServers.size())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  SetNameServers(kTestNameServers, /*validate=*/true);

  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);
}

TEST_F(ResolverTest, Resolve_DNSDoHServersFallbackNotValidated) {
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _))
      .Times(kTestNameServers.size())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  SetNameServers(kTestNameServers);
  SetDoHProviders(kTestDoHProviders);

  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);
}

TEST_F(ResolverTest, Resolve_DNSDoHServersFallbackPartiallyValidated) {
  SetNameServers(kTestNameServers);
  SetDoHProviders(kTestDoHProviders);

  const auto& validated_name_server = kTestNameServers.front();
  auto probe_state = std::make_unique<Resolver::ProbeState>(
      validated_name_server, /*doh=*/false);
  resolver_->HandleDo53ProbeResult(probe_state->weak_factory.GetWeakPtr(), {},
                                   ARES_SUCCESS, nullptr, 0);

  EXPECT_CALL(*ares_client_, Resolve(_, _, _, validated_name_server, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);
}

TEST_F(ResolverTest, Resolve_DNSDoHServersFallbackValidated) {
  SetNameServers(kTestNameServers, /*validate=*/true);
  SetDoHProviders(kTestDoHProviders, /*validate=*/true);

  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _))
      .Times(kTestNameServers.size())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr(), true);
  EXPECT_GT(sock_fd->num_active_queries, 0);
}

TEST_F(ResolverTest, CurlResult_CURLFail) {
  SetNameServers(kTestNameServers, /*validate=*/true);
  SetDoHProviders(kTestDoHProviders, /*validate=*/true);

  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);

  // Expect query to be done with Do53.
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _))
      .Times(kTestNameServers.size())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  // All curl results failed with curl error.
  DoHCurlClient::CurlResult res(CURLE_COULDNT_CONNECT, 0 /* http_code */,
                                0 /* timeout */);
  for (int i = 0; i < kTestDoHProviders.size(); i++) {
    resolver_->HandleCurlResult(sock_fd->weak_factory.GetWeakPtr(), nullptr,
                                res, nullptr, 0);
  }
  task_environment_.RunUntilIdle();
}

TEST_F(ResolverTest, CurlResult_HTTPError) {
  SetNameServers(kTestNameServers, /*validate=*/true);
  SetDoHProviders(kTestDoHProviders, /*validate=*/true);

  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);

  // Expect query to be done with Do53.
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _))
      .Times(kTestNameServers.size())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  // All curl results failed with a HTTP error.
  DoHCurlClient::CurlResult res(CURLE_OK, 403 /* http_code */, 0 /*timeout*/);
  for (int i = 0; i < kTestDoHProviders.size(); i++) {
    resolver_->HandleCurlResult(sock_fd->weak_factory.GetWeakPtr(), nullptr,
                                res, nullptr, 0);
  }
  task_environment_.RunUntilIdle();
}

TEST_F(ResolverTest, CurlResult_SuccessNoRetry) {
  SetNameServers(kTestNameServers, /*validate=*/true);
  SetDoHProviders(kTestDoHProviders, /*validate=*/true);

  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);

  // Expect no more queries.
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  DoHCurlClient::CurlResult res(CURLE_OK, 200 /* http_code */, 0 /*timeout*/);
  for (int i = 0; i < kTestDoHProviders.size(); i++) {
    resolver_->HandleCurlResult(sock_fd->weak_factory.GetWeakPtr(), nullptr,
                                res, nullptr, 0);
  }
  task_environment_.RunUntilIdle();
}

TEST_F(ResolverTest, CurlResult_CurlErrorNoRetry) {
  SetNameServers(kTestNameServers, /*validate=*/true);
  SetDoHProviders(kTestDoHProviders, /*validate=*/true, /*always_on_doh=*/true);

  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);

  // Expect no more queries.
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  DoHCurlClient::CurlResult res(CURLE_OUT_OF_MEMORY, 0 /* http_code */,
                                0 /* timeout */);
  for (int i = 0; i < kTestDoHProviders.size(); i++) {
    resolver_->HandleCurlResult(sock_fd->weak_factory.GetWeakPtr(), nullptr,
                                res, nullptr, 0);
  }
  task_environment_.RunUntilIdle();
}

TEST_F(ResolverTest, CurlResult_HTTPErrorNoRetry) {
  SetNameServers(kTestNameServers, /*validate=*/true);
  SetDoHProviders(kTestDoHProviders, /*validate=*/true, /*always_on_doh=*/true);

  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);

  // Expect no more queries.
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  DoHCurlClient::CurlResult res(CURLE_OK, 403 /* http_code */, 0 /* timeout*/);
  for (int i = 0; i < kTestDoHProviders.size(); i++) {
    resolver_->HandleCurlResult(sock_fd->weak_factory.GetWeakPtr(), nullptr,
                                res, nullptr, 0);
  }
  task_environment_.RunUntilIdle();
}

TEST_F(ResolverTest, CurlResult_FailTooManyRetries) {
  SetNameServers(kTestNameServers, /*validate=*/true);
  SetDoHProviders(kTestDoHProviders, /*validate=*/true);

  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_STREAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);

  // Expect no more queries.
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  sock_fd->num_retries = INT_MAX;
  DoHCurlClient::CurlResult res(CURLE_OK, 429 /* http_code */, 0 /*timeout*/);
  for (int i = 0; i < kTestDoHProviders.size(); i++) {
    resolver_->HandleCurlResult(sock_fd->weak_factory.GetWeakPtr(), nullptr,
                                res, nullptr, 0);
  }
  task_environment_.RunUntilIdle();
}

TEST_F(ResolverTest, HandleAresResult_Success) {
  SetNameServers(kTestNameServers, /*validate=*/true);

  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_DGRAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);

  // Expect no more queries.
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _)).Times(0);

  sock_fd->num_retries = INT_MAX;
  for (int i = 0; i < kTestNameServers.size(); i++) {
    resolver_->HandleAresResult(sock_fd->weak_factory.GetWeakPtr(), nullptr,
                                ARES_SUCCESS, nullptr, 0);
  }
  task_environment_.RunUntilIdle();
}

TEST_F(ResolverTest, ConstructServFailResponse_ValidQuery) {
  const char kDnsQuery[] = {'J',    'G',    '\x01', ' ',    '\x00', '\x01',
                            '\x00', '\x00', '\x00', '\x00', '\x00', '\x01',
                            '\x06', 'g',    'o',    'o',    'g',    'l',
                            'e',    '\x03', 'c',    'o',    'm',    '\x00',
                            '\x00', '\x01', '\x00', '\x01'};
  const char kServFailResponse[] = {
      'J',    'G',    '\x80', '\x02', '\x00', '\x01', '\x00',
      '\x00', '\x00', '\x00', '\x00', '\x00', '\x06', 'g',
      'o',    'o',    'g',    'l',    'e',    '\x03', 'c',
      'o',    'm',    '\x00', '\x00', '\x01', '\x00', '\x01'};
  patchpanel::DnsResponse response =
      resolver_->ConstructServFailResponse(kDnsQuery, sizeof(kDnsQuery));
  std::vector<char> response_data(
      response.io_buffer()->data(),
      response.io_buffer()->data() + response.io_buffer_size());
  EXPECT_THAT(response_data, ElementsAreArray(kServFailResponse));
}

TEST_F(ResolverTest, ConstructServFailResponse_BadLength) {
  const char kDnsQuery[] = {'J',    'G',    '\x01', ' ',    '\x00', '\x01',
                            '\x00', '\x00', '\x00', '\x00', '\x00', '\x01',
                            '\x06', 'g',    'o',    'o',    'g',    'l',
                            'e',    '\x03', 'c',    'o',    'm',    '\x00',
                            '\x00', '\x01', '\x00', '\x01'};
  const char kServFailResponse[] = {'\x00', '\x00', '\x80', '\x02',
                                    '\x00', '\x00', '\x00', '\x00',
                                    '\x00', '\x00', '\x00', '\x00'};
  patchpanel::DnsResponse response =
      resolver_->ConstructServFailResponse(kDnsQuery, -1);
  std::vector<char> response_data(
      response.io_buffer()->data(),
      response.io_buffer()->data() + response.io_buffer_size());
  EXPECT_THAT(response_data, ElementsAreArray(kServFailResponse));
}

TEST_F(ResolverTest, ConstructServFailResponse_BadQuery) {
  const char kDnsQuery[] = {'g', 'o',    'o', 'g', 'l',
                            'e', '\x03', 'c', 'o', 'm'};
  const char kServFailResponse[] = {'\x00', '\x00', '\x80', '\x02',
                                    '\x00', '\x00', '\x00', '\x00',
                                    '\x00', '\x00', '\x00', '\x00'};
  patchpanel::DnsResponse response =
      resolver_->ConstructServFailResponse(kDnsQuery, sizeof(kDnsQuery));
  std::vector<char> response_data(
      response.io_buffer()->data(),
      response.io_buffer()->data() + response.io_buffer_size());
  EXPECT_THAT(response_data, ElementsAreArray(kServFailResponse));
}

TEST_F(ResolverTest, Probe_Started) {
  resolver_->SetProbingEnabled(true);

  for (const auto& name_server : kTestNameServers) {
    EXPECT_CALL(*ares_client_, Resolve(_, _, _, name_server, _))
        .WillOnce(Return(true));
  }
  for (const auto& doh_provider : kTestDoHProviders) {
    EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, doh_provider))
        .WillOnce(Return(true));
  }

  resolver_->SetNameServers(kTestNameServers);
  resolver_->SetDoHProviders(kTestDoHProviders);
}

TEST_F(ResolverTest, Probe_SetNameServers) {
  resolver_->SetProbingEnabled(true);

  auto name_servers = kTestNameServers;
  for (const auto& name_server : name_servers) {
    EXPECT_CALL(*ares_client_, Resolve(_, _, _, name_server, _))
        .WillOnce(Return(true));
  }

  const auto& new_name_server = "9.9.9.9";
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, new_name_server, _)).Times(0);

  resolver_->SetNameServers(name_servers);

  name_servers.push_back(new_name_server);

  // Check that only the newly added name servers are probed.
  for (const auto& name_server : name_servers) {
    EXPECT_CALL(*ares_client_, Resolve(_, _, _, name_server, _)).Times(0);
  }
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, new_name_server, _))
      .WillOnce(Return(true));

  resolver_->SetNameServers(name_servers);
}

TEST_F(ResolverTest, Probe_SetDoHProviders) {
  resolver_->SetProbingEnabled(true);

  auto doh_providers = kTestDoHProviders;
  for (const auto& doh_provider : doh_providers) {
    EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, doh_provider))
        .WillOnce(Return(true));
  }

  const auto& new_doh_provider = "https://dns3.google/dns-query";
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, new_doh_provider)).Times(0);

  resolver_->SetNameServers(kTestNameServers);
  resolver_->SetDoHProviders(doh_providers);

  doh_providers.push_back(new_doh_provider);

  // Check that only the newly added DoH providers and name servers are probed.
  for (const auto& doh_provider : doh_providers) {
    EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, doh_provider)).Times(0);
  }
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, new_doh_provider))
      .WillOnce(Return(true));

  resolver_->SetDoHProviders(doh_providers);
}

TEST_F(ResolverTest, Probe_InvalidateNameServer) {
  auto name_servers = kTestNameServers;
  resolver_->SetNameServers(name_servers);

  // Validate name servers.
  for (const auto& name_server : name_servers) {
    auto probe_state =
        std::make_unique<Resolver::ProbeState>(name_server, /*doh=*/false);
    resolver_->HandleDo53ProbeResult(probe_state->weak_factory.GetWeakPtr(), {},
                                     ARES_SUCCESS, nullptr, 0);
  }

  // Invalidate a name server.
  auto invalidated_name_server = name_servers.back();
  name_servers.pop_back();

  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_DGRAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);

  auto validated_probe_state = std::make_unique<Resolver::ProbeState>(
      invalidated_name_server, /*doh=*/false, /*validated=*/true);
  resolver_->HandleAresResult(sock_fd->weak_factory.GetWeakPtr(),
                              validated_probe_state->weak_factory.GetWeakPtr(),
                              ARES_ETIMEOUT, nullptr, 0);
  for (const auto& name_server : name_servers) {
    auto probe_state =
        std::make_unique<Resolver::ProbeState>(name_server, /*doh=*/false);
    resolver_->HandleAresResult(sock_fd->weak_factory.GetWeakPtr(),
                                probe_state->weak_factory.GetWeakPtr(),
                                ARES_SUCCESS, nullptr, 0);
  }

  // Query should be done using all name servers except the invalidated one.
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, invalidated_name_server, _))
      .Times(0);
  for (const auto& name_server : name_servers) {
    EXPECT_CALL(*ares_client_, Resolve(_, _, _, name_server, _))
        .WillOnce(Return(true));
  }

  auto fd_check = std::make_unique<Resolver::SocketFd>(SOCK_DGRAM, 0);
  resolver_->Resolve(fd_check->weak_factory.GetWeakPtr());
  EXPECT_GT(fd_check->num_active_queries, 0);
}

TEST_F(ResolverTest, Probe_InvalidateDoHProvider) {
  auto doh_providers = kTestDoHProviders;
  resolver_->SetNameServers(kTestNameServers);
  resolver_->SetDoHProviders(doh_providers);

  // Validate DoH providers.
  for (const auto& doh_provider : doh_providers) {
    auto probe_state =
        std::make_unique<Resolver::ProbeState>(doh_provider, /*doh=*/true);
    DoHCurlClient::CurlResult res(CURLE_OK, 200 /* http_code */,
                                  0 /* timeout */);
    resolver_->HandleDoHProbeResult(probe_state->weak_factory.GetWeakPtr(), {},
                                    res, nullptr, 0);
  }

  // Invalidate a DoH provider.
  auto invalidated_doh_provider = doh_providers.back();
  doh_providers.pop_back();

  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_DGRAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);

  auto validated_probe_state = std::make_unique<Resolver::ProbeState>(
      invalidated_doh_provider, /*doh=*/true, /*validated=*/true);
  DoHCurlClient::CurlResult res_fail(CURLE_OUT_OF_MEMORY, 0 /* http_code */,
                                     0 /* timeout */);
  resolver_->HandleCurlResult(sock_fd->weak_factory.GetWeakPtr(),
                              validated_probe_state->weak_factory.GetWeakPtr(),
                              res_fail, nullptr, 0);
  DoHCurlClient::CurlResult res_success(CURLE_OK, 200 /* http_code */,
                                        0 /* timeout */);
  for (const auto& doh_provider : doh_providers) {
    auto probe_state =
        std::make_unique<Resolver::ProbeState>(doh_provider, /*doh=*/true);
    resolver_->HandleCurlResult(sock_fd->weak_factory.GetWeakPtr(),
                                probe_state->weak_factory.GetWeakPtr(),
                                res_success, nullptr, 0);
  }

  // Query should be done using all DoH providers except the invalidated one.
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, invalidated_doh_provider))
      .Times(0);
  for (const auto& doh_provider : doh_providers) {
    EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, doh_provider))
        .WillOnce(Return(true));
  }

  auto fd_check = std::make_unique<Resolver::SocketFd>(SOCK_DGRAM, 0);
  resolver_->Resolve(fd_check->weak_factory.GetWeakPtr());
  EXPECT_GT(fd_check->num_active_queries, 0);
}

TEST_F(ResolverTest, Probe_Do53ProbeRestarted) {
  auto name_servers = kTestNameServers;
  resolver_->SetNameServers(name_servers);

  // Validate name servers.
  for (const auto& name_server : name_servers) {
    auto probe_state =
        std::make_unique<Resolver::ProbeState>(name_server, /*doh=*/false);
    resolver_->HandleDo53ProbeResult(probe_state->weak_factory.GetWeakPtr(), {},
                                     ARES_SUCCESS, nullptr, 0);
  }

  // Invalidate a name server.
  auto invalidated_name_server = name_servers.back();
  name_servers.pop_back();

  EXPECT_CALL(*ares_client_, Resolve(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_DGRAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);

  // Expect probe to be restarted only for the invalidated name server.
  EXPECT_CALL(*ares_client_, Resolve(_, _, _, invalidated_name_server, _))
      .WillOnce(Return(true));
  for (const auto& name_server : name_servers) {
    EXPECT_CALL(*ares_client_, Resolve(_, _, _, name_server, _)).Times(0);
  }
  resolver_->SetProbingEnabled(true);

  auto validated_probe_state = std::make_unique<Resolver::ProbeState>(
      invalidated_name_server, /*doh=*/false, /*validated=*/true);
  resolver_->HandleAresResult(sock_fd->weak_factory.GetWeakPtr(),
                              validated_probe_state->weak_factory.GetWeakPtr(),
                              ARES_ETIMEOUT, nullptr, 0);
  for (const auto& name_server : name_servers) {
    auto probe_state =
        std::make_unique<Resolver::ProbeState>(name_server, /*doh=*/false);
    resolver_->HandleAresResult(sock_fd->weak_factory.GetWeakPtr(),
                                probe_state->weak_factory.GetWeakPtr(),
                                ARES_SUCCESS, nullptr, 0);
  }
}

TEST_F(ResolverTest, Probe_DoHProbeRestarted) {
  auto doh_providers = kTestDoHProviders;
  resolver_->SetNameServers(kTestNameServers);
  resolver_->SetDoHProviders(doh_providers);

  // Validate DoH providers.
  for (const auto& doh_provider : doh_providers) {
    auto probe_state =
        std::make_unique<Resolver::ProbeState>(doh_provider, /*doh=*/true);
    DoHCurlClient::CurlResult res(CURLE_OK, 200 /* http_code */,
                                  0 /* timeout */);
    resolver_->HandleDoHProbeResult(probe_state->weak_factory.GetWeakPtr(), {},
                                    res, nullptr, 0);
  }

  // Invalidate a DoH provider.
  auto invalidated_doh_provider = doh_providers.back();
  doh_providers.pop_back();

  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  auto sock_fd = std::make_unique<Resolver::SocketFd>(SOCK_DGRAM, 0);
  resolver_->Resolve(sock_fd->weak_factory.GetWeakPtr());
  EXPECT_GT(sock_fd->num_active_queries, 0);

  // Expect probe to be restarted only for the invalidated DoH provider.
  EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, invalidated_doh_provider))
      .WillOnce(Return(true));
  for (const auto& doh_provider : doh_providers) {
    EXPECT_CALL(*curl_client_, Resolve(_, _, _, _, doh_provider)).Times(0);
  }
  resolver_->SetProbingEnabled(true);

  auto validated_probe_state = std::make_unique<Resolver::ProbeState>(
      invalidated_doh_provider, /*doh=*/true, /*validated=*/true);
  DoHCurlClient::CurlResult res_fail(CURLE_OUT_OF_MEMORY, 0 /* http_code */,
                                     0 /* timeout */);
  resolver_->HandleCurlResult(sock_fd->weak_factory.GetWeakPtr(),
                              validated_probe_state->weak_factory.GetWeakPtr(),
                              res_fail, nullptr, 0);
  DoHCurlClient::CurlResult res_success(CURLE_OK, 200 /* http_code */,
                                        0 /* timeout */);
  for (const auto& doh_provider : doh_providers) {
    auto probe_state =
        std::make_unique<Resolver::ProbeState>(doh_provider, /*doh=*/true);
    resolver_->HandleCurlResult(sock_fd->weak_factory.GetWeakPtr(),
                                probe_state->weak_factory.GetWeakPtr(),
                                res_success, nullptr, 0);
  }
}
}  // namespace dns_proxy
