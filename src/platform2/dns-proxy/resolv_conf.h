// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DNS_PROXY_RESOLV_CONF_H_
#define DNS_PROXY_RESOLV_CONF_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/memory/ref_counted.h>
#include <base/no_destructor.h>

namespace dns_proxy {

// Helper class to write name server(s) into a "resolv.conf" formatted file.
class ResolvConf {
 public:
  ResolvConf();
  ResolvConf(const ResolvConf&) = delete;
  ResolvConf& operator=(const ResolvConf&) = delete;

  virtual ~ResolvConf();

  virtual void set_path(const base::FilePath& path) { path_ = path; }

  // Install domain name service parameters, given a list of
  // DNS servers in |name_servers|, and a list of DNS search suffixes in
  // |domain_search_list|.
  virtual bool SetDNSFromLists(
      const std::vector<std::string>& name_servers,
      const std::vector<std::string>& domain_search_list);

  // Tells the resolver that DNS should go through the proxy address(es)
  // provided. If |proxy_addrs| is non-empty, this name server will be used
  // instead of any provided by SetDNSFromLists. Previous name servers are not
  // forgotten, and will be restored if this method is called again with
  // |proxy_addrs| empty.
  virtual bool SetDNSProxyAddresses(
      const std::vector<std::string>& proxy_addrs);

 private:
  friend class ResolvConfTest;
  friend class base::NoDestructor<ResolvConf>;

  // Writes the resolver file.
  bool Emit();

  base::FilePath path_;
  std::vector<std::string> name_servers_;
  std::vector<std::string> domain_search_list_;
  std::vector<std::string> dns_proxy_addrs_;
};

}  // namespace dns_proxy

#endif  // DNS_PROXY_RESOLV_CONF_H_
