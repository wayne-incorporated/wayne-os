// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/resolver.h"

#include <string>
#include <vector>

#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

#include "shill/dns_util.h"
#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/net/ip_address.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kResolver;
}  // namespace Logging

const char Resolver::kDefaultIgnoredSearchList[] = "gateway.2wire.net";

Resolver::Resolver() = default;

Resolver::~Resolver() = default;

Resolver* Resolver::GetInstance() {
  static base::NoDestructor<Resolver> instance;
  return instance.get();
}

bool Resolver::SetDNSFromLists(
    const std::vector<std::string>& name_servers,
    const std::vector<std::string>& domain_search_list) {
  SLOG(2) << __func__;

  name_servers_ = name_servers;
  domain_search_list_ = domain_search_list;
  return Emit();
}

bool Resolver::Emit() {
  if (path_.empty()) {
    LOG(DFATAL) << "No path set";
    return false;
  }

  // dns-proxy always used if set.
  const auto name_servers =
      !dns_proxy_addrs_.empty() ? dns_proxy_addrs_ : name_servers_;
  if (name_servers.empty() && domain_search_list_.empty()) {
    SLOG(2) << "DNS list is empty";
    return ClearDNS();
  }

  std::vector<std::string> lines;
  for (const auto& server : name_servers) {
    const auto addr = IPAddress::CreateFromString(server);
    if (!addr.has_value()) {
      LOG(WARNING) << "Malformed nameserver IP: " << server;
      continue;
    }
    lines.push_back("nameserver " + addr->ToString());
  }

  std::vector<std::string> filtered_domain_search_list;
  for (const auto& domain : domain_search_list_) {
    if (base::Contains(ignored_search_list_, domain)) {
      continue;
    }
    if (IsValidDNSDomain(domain)) {
      filtered_domain_search_list.push_back(domain);
    } else {
      LOG(WARNING) << "Malformed search domain: " << domain;
    }
  }

  if (!filtered_domain_search_list.empty()) {
    lines.push_back("search " +
                    base::JoinString(filtered_domain_search_list, " "));
  }

  // - Send queries one-at-a-time, rather than parallelizing IPv4
  //   and IPv6 queries for a single host.
  // - Override the default 5-second request timeout and use a
  //   1-second timeout instead. (NOTE: Chrome's ADNS will use
  //   one second, regardless of what we put here.)
  // - Allow 5 attempts, rather than the default of 2.
  //   - For glibc, the worst case number of queries will be
  //        attempts * count(servers) * (count(search domains)+1)
  //   - For Chrome, the worst case number of queries will be
  //        attempts * count(servers) + 3 * glibc
  //   See crbug.com/224756 for supporting data.
  lines.push_back("options single-request timeout:1 attempts:5");

  // Newline at end of file
  lines.push_back("");

  const auto contents = base::JoinString(lines, "\n");

  SLOG(2) << "Writing DNS out to " << path_.value();
  int count = base::WriteFile(path_, contents.c_str(), contents.size());

  return count == static_cast<int>(contents.size());
}

bool Resolver::SetDNSProxyAddresses(
    const std::vector<std::string>& proxy_addrs) {
  SLOG(2) << __func__;

  dns_proxy_addrs_ = proxy_addrs;
  return Emit();
}

bool Resolver::ClearDNS() {
  SLOG(2) << __func__;

  if (path_.empty()) {
    LOG(DFATAL) << "No path set";
    return false;
  }

  name_servers_.clear();
  domain_search_list_.clear();
  dns_proxy_addrs_.clear();
  return base::DeleteFile(path_);
}

}  // namespace shill
