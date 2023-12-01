// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSDNS_HOSTS_MODIFIER_H_
#define CROSDNS_HOSTS_MODIFIER_H_

#include <map>
#include <string>

#include <base/files/file_path.h>

namespace crosdns {

// Class for writing out modifications to a hosts file such as /etc/hosts.
class HostsModifier {
 public:
  HostsModifier();
  HostsModifier(const HostsModifier&) = delete;
  HostsModifier& operator=(const HostsModifier&) = delete;

  ~HostsModifier();

  // Upon loading, this class will read in the file at the specified path and
  // use it as a baseline for any modifications it writes out. It will also look
  // for its marker line in that file and then exclude anything after that line
  // in case it is recovering from a crash.
  bool Init(const base::FilePath& hosts_filepath);

  // Sets a hostname mapping in the /etc/hosts file. Only IPv4 is supported for
  // now, the |ipv4| parameter must not be empty. The |ipv4| parameter is
  // currently ignored. Returns true on success. If failure and |err_out| is
  // not null, it will be set to the error message. The /etc/hosts file will be
  // automatically written to before this call completes.
  bool SetHostnameIpMapping(const std::string& hostname,
                            const std::string& ipv4,
                            const std::string& ipv6,
                            std::string* err_out);

  // Removes a hostname mapping from the /etc/hosts file. Returns true on
  // success. If there is a failure and |err_out| is not null, |err_out| is set
  // to the error message. The /etc/hosts file will be automatically written to
  // before this call completes.
  bool RemoveHostnameIpMapping(const std::string& hostname,
                               std::string* err_out);

 private:
  // Writes out the updated hosts file.
  bool WriteHostsFile();

  // Filepath to the /etc/hosts file so we can override for unit testing.
  base::FilePath filepath_;

  // This is what was in the file to start with that we always write out as the
  // prefix.
  std::string base_hosts_contents_;

  // Mapping of hostnames to ipv4 addresses.
  std::map<std::string, std::string> hostname_ipv4_map_;
};

}  // namespace crosdns

#endif  // CROSDNS_HOSTS_MODIFIER_H_
