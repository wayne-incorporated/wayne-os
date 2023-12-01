// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/resolver.h"

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

using testing::Test;

namespace shill {

namespace {
const char kNameServer0[] = "8.8.8.8";
const char kNameServer1[] = "8.8.9.9";
const char kNameServer2[] = "2001:4860:4860:0:0:0:0:8888";
const char kNameServerEvil[] = "8.8.8.8\noptions debug";
const char kNameServerSubtlyEvil[] = "3.14.159.265";
const char kNameServerProxy[] = "100.115.94.1";
const char kSearchDomain0[] = "chromium.org";
const char kSearchDomain1[] = "google.com";
const char kSearchDomain2[] = "crbug.com";
const char kSearchDomainEvil[] = "google.com\nnameserver 6.6.6.6";
const char kSearchDomainSubtlyEvil[] = "crate&barrel.com";
const char kExpectedOutput[] =
    "nameserver 8.8.8.8\n"
    "nameserver 8.8.9.9\n"
    "nameserver 2001:4860:4860::8888\n"
    "search chromium.org google.com\n"
    "options single-request timeout:1 attempts:5\n";
const char kExpectedIgnoredSearchOutput[] =
    "nameserver 8.8.8.8\n"
    "nameserver 8.8.9.9\n"
    "nameserver 2001:4860:4860::8888\n"
    "search google.com\n"
    "options single-request timeout:1 attempts:5\n";
const char kExpectedProxyOutput[] =
    "nameserver 100.115.94.1\n"
    "options single-request timeout:1 attempts:5\n";
const char kExpectedProxyWithSearchOutput[] =
    "nameserver 100.115.94.1\n"
    "search chromium.org google.com\n"
    "options single-request timeout:1 attempts:5\n";
}  // namespace

class ResolverTest : public Test {
 public:
  ResolverTest() : resolver_(Resolver::GetInstance()) {}

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    path_ = temp_dir_.GetPath().Append("resolver");
    resolver_->set_path(path_);
    EXPECT_FALSE(base::PathExists(path_));
    EXPECT_TRUE(resolver_->ClearDNS());
  }

  void TearDown() override {
    EXPECT_TRUE(resolver_->ClearDNS());
    resolver_->set_path(base::FilePath(""));  // Don't try to save the store.
    ASSERT_TRUE(temp_dir_.Delete());
    resolver_->set_ignored_search_list({});
  }

 protected:
  std::string ReadFile();

  base::ScopedTempDir temp_dir_;
  Resolver* resolver_;
  base::FilePath path_;
};

std::string ResolverTest::ReadFile() {
  std::string data;
  EXPECT_TRUE(base::ReadFileToString(resolver_->path_, &data));
  return data;
}

TEST_F(ResolverTest, NonEmpty) {
  std::vector<std::string> dns_servers = {kNameServer0, kNameServer1,
                                          kNameServer2};
  std::vector<std::string> domain_search = {kSearchDomain0, kSearchDomain1};

  EXPECT_TRUE(resolver_->SetDNSFromLists(dns_servers, domain_search));
  EXPECT_TRUE(base::PathExists(path_));
  EXPECT_EQ(kExpectedOutput, ReadFile());
}

TEST_F(ResolverTest, Sanitize) {
  std::vector<std::string> dns_servers = {kNameServer0, kNameServerEvil,
                                          kNameServer1, kNameServerSubtlyEvil,
                                          kNameServer2};
  std::vector<std::string> domain_search = {kSearchDomainEvil, kSearchDomain0,
                                            kSearchDomain1,
                                            kSearchDomainSubtlyEvil};

  EXPECT_TRUE(resolver_->SetDNSFromLists(dns_servers, domain_search));
  EXPECT_TRUE(base::PathExists(path_));
  EXPECT_EQ(kExpectedOutput, ReadFile());
}

TEST_F(ResolverTest, Empty) {
  std::vector<std::string> dns_servers;
  std::vector<std::string> domain_search;

  EXPECT_TRUE(resolver_->SetDNSFromLists(dns_servers, domain_search));
}

TEST_F(ResolverTest, IgnoredSearchList) {
  std::vector<std::string> dns_servers = {kNameServer0, kNameServer1,
                                          kNameServer2};
  std::vector<std::string> domain_search = {kSearchDomain0, kSearchDomain1};
  std::vector<std::string> ignored_search = {kSearchDomain0, kSearchDomain2};
  resolver_->set_ignored_search_list(ignored_search);
  EXPECT_TRUE(resolver_->SetDNSFromLists(dns_servers, domain_search));
  EXPECT_TRUE(base::PathExists(path_));
  EXPECT_EQ(kExpectedIgnoredSearchOutput, ReadFile());
}

TEST_F(ResolverTest, Proxy) {
  EXPECT_TRUE(resolver_->SetDNSProxyAddresses({kNameServerProxy}));
  EXPECT_TRUE(base::PathExists(path_));
  EXPECT_EQ(kExpectedProxyOutput, ReadFile());
}

TEST_F(ResolverTest, ProxyClear) {
  EXPECT_TRUE(resolver_->SetDNSProxyAddresses({kNameServerProxy}));
  EXPECT_TRUE(base::PathExists(path_));
  EXPECT_TRUE(resolver_->SetDNSProxyAddresses({}));
  EXPECT_FALSE(base::PathExists(path_));
}

TEST_F(ResolverTest, ProxyToggle) {
  std::vector<std::string> dns_servers = {kNameServer0, kNameServer1,
                                          kNameServer2};
  std::vector<std::string> domain_search = {kSearchDomain0, kSearchDomain1};
  // Connection's DNS
  EXPECT_TRUE(resolver_->SetDNSFromLists(dns_servers, domain_search));
  EXPECT_TRUE(base::PathExists(path_));
  EXPECT_EQ(kExpectedOutput, ReadFile());
  // DNS proxy set
  EXPECT_TRUE(resolver_->SetDNSProxyAddresses({kNameServerProxy}));
  EXPECT_TRUE(base::PathExists(path_));
  EXPECT_EQ(kExpectedProxyWithSearchOutput, ReadFile());
  // Connection DNS update (no change to resolv.conf)
  EXPECT_TRUE(resolver_->SetDNSFromLists(dns_servers, domain_search));
  EXPECT_TRUE(base::PathExists(path_));
  EXPECT_EQ(kExpectedProxyWithSearchOutput, ReadFile());
  // DNS proxy cleared
  EXPECT_TRUE(resolver_->SetDNSProxyAddresses({}));
  EXPECT_TRUE(base::PathExists(path_));
  EXPECT_EQ(kExpectedOutput, ReadFile());
}

}  // namespace shill
