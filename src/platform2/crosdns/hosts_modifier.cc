// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crosdns/hosts_modifier.h"

#include <arpa/inet.h>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

namespace {
// To avoid reading something too big, this should never happen.
constexpr size_t kMaxFileSize = 1048576;  // 1MB.
// This is the delimiter we write out before our changes so that if we crash and
// are restarted we know what the base file was before we modified it.
constexpr char kFileModificationDelimeter[] =
    "\n#####DYNAMIC-CROSDNS-ENTRIES#####\n";
constexpr char kAllowedHostnameSuffix[] = ".linux.test";
constexpr uint32_t kAllowedIpSubnet = 0x64735c00;  // 100.115.92.0
constexpr uint32_t kAllowedIpMask = 0xFFFFFF00;

// Only allow IPs in the 100.115.92.0/24 subnet.
bool IsAllowedIpv4Address(uint32_t ipv4, std::string* err_out) {
  if ((ipv4 & kAllowedIpMask) != kAllowedIpSubnet) {
    *err_out = "IP address disallowed in mapping";
    return false;
  }
  return true;
}

// Hostname must be *.test and use legal chars.
bool IsAllowedHostname(const std::string& hostname, std::string* err_out) {
  // Make sure this is a legal hostname. It must be comprised of alphanumeric
  // characters, dashes or dots. The dot or dash may not be the first character.
  // It may not have consecutive dots. It must also have the '.test' suffix.
  if (!base::EndsWith(hostname, kAllowedHostnameSuffix,
                      base::CompareCase::SENSITIVE)) {
    *err_out = "Attempt to add invalid hostname to mapping of: " + hostname;
    return false;
  }
  if (hostname[0] == '-' || hostname[0] == '.') {
    *err_out = "First char in hostname may not be a dot or dash: " + hostname;
    return false;
  }
  bool last_was_dot = false;
  for (auto c : hostname) {
    if (!base::IsAsciiAlpha(c) && !base::IsAsciiDigit(c) && c != '-') {
      if (c == '.' && !last_was_dot) {
        last_was_dot = true;
        continue;
      }
      *err_out = "Invalid char in hostname: " + hostname;
      return false;
    }
    last_was_dot = false;
  }
  return true;
}
}  // namespace

namespace crosdns {

HostsModifier::HostsModifier() = default;
HostsModifier::~HostsModifier() = default;

bool HostsModifier::Init(const base::FilePath& hosts_filepath) {
  filepath_ = hosts_filepath;
  if (!base::ReadFileToStringWithMaxSize(filepath_, &base_hosts_contents_,
                                         kMaxFileSize)) {
    PLOG(ERROR) << "Failed reading in existing hostname file from "
                << filepath_.value();
    return false;
  }
  // See if our delimiter was in there or not, if it is then we strip everything
  // off after it (including the delimiter) and then rewrite out the file so
  // that any stale entries are removed.
  size_t delim_pos = base_hosts_contents_.find(kFileModificationDelimeter);
  if (delim_pos == std::string::npos) {
    return true;
  }
  // Delimeter was in there, strip it off and rewrite the file.
  base_hosts_contents_.erase(delim_pos);
  return WriteHostsFile();
}

bool HostsModifier::SetHostnameIpMapping(const std::string& hostname,
                                         const std::string& ipv4,
                                         const std::string& ipv6,
                                         std::string* err_out) {
  CHECK(err_out);
  uint32_t int_ip;
  if (inet_pton(AF_INET, ipv4.c_str(), &int_ip) != 1) {
    *err_out = "Failed parsing IPv4 address: " + ipv4;
    return false;
  }
  int_ip = htonl(int_ip);
  if (!IsAllowedIpv4Address(int_ip, err_out)) {
    return false;
  }
  // TODO(jkardatzke): Add IPv6 support when it is needed.
  if (!IsAllowedHostname(hostname, err_out)) {
    return false;
  }
  hostname_ipv4_map_[hostname] = ipv4;
  if (!WriteHostsFile()) {
    *err_out = "Failed writing the updated /etc/hosts file";
    return false;
  }
  return true;
}

bool HostsModifier::RemoveHostnameIpMapping(const std::string& hostname,
                                            std::string* err_out) {
  CHECK(err_out);
  if (!hostname_ipv4_map_.erase(hostname)) {
    *err_out =
        "Attempt to remove non-existent hostname mapping for: " + hostname;
    return false;
  }
  if (!WriteHostsFile()) {
    *err_out = "Failed writing the updated /etc/hosts file";
    return false;
  }
  return true;
}

bool HostsModifier::WriteHostsFile() {
  // We first write this to an adjacent temp file and then atomically rename
  // that file to be our target aftewards.
  base::FilePath temp_file_path;
  if (!base::CreateTemporaryFileInDir(filepath_.DirName(), &temp_file_path)) {
    PLOG(ERROR) << "Failed creating temp file in dir for hostname writing "
                << filepath_.DirName().value();
    return false;
  }

  // Open our file for writing.
  base::File temp_file(temp_file_path,
                       base::File::FLAG_OPEN | base::File::FLAG_WRITE);
  if (!temp_file.IsValid()) {
    PLOG(ERROR) << "Failed opening temp file for writing: "
                << temp_file_path.value();
    return false;
  }

  // First write out the base contents for the file.
  if (temp_file.WriteAtCurrentPos(base_hosts_contents_.c_str(),
                                  base_hosts_contents_.size()) !=
      base_hosts_contents_.size()) {
    PLOG(ERROR) << "Failed writing base contents to temp file: "
                << temp_file_path.value();
    return false;
  }
  // We only write out more if we have contents in our map.
  if (!hostname_ipv4_map_.empty()) {
    // Now write out our delimiter, which includes newlines at both ends so we
    // are sure it is on its own line and we will be on a new line after this.
    if (temp_file.WriteAtCurrentPos(kFileModificationDelimeter,
                                    sizeof(kFileModificationDelimeter) - 1) !=
        sizeof(kFileModificationDelimeter) - 1) {
      PLOG(ERROR) << "Failed writing delimiter to temp file: "
                  << temp_file_path.value();
      return false;
    }

    // Now write out all of our entries, one per line.
    for (const auto& entry : hostname_ipv4_map_) {
      std::string curr_line = base::StringPrintf(
          "%s %s\n", entry.second.c_str(), entry.first.c_str());
      if (temp_file.WriteAtCurrentPos(curr_line.c_str(), curr_line.size()) !=
          curr_line.size()) {
        PLOG(ERROR) << "Failed writing hostname entry to temp file: "
                    << temp_file_path.value();
        return false;
      }
    }
  }

  // Done writing to the file, close it, ensure permissions are correct and
  // rename it.
  temp_file.Close();
  if (!base::SetPosixFilePermissions(temp_file_path,
                                     base::FILE_PERMISSION_READ_BY_USER |
                                         base::FILE_PERMISSION_READ_BY_GROUP |
                                         base::FILE_PERMISSION_READ_BY_OTHERS |
                                         base::FILE_PERMISSION_WRITE_BY_USER)) {
    PLOG(ERROR) << "Failed setting file permissions on our temp file: "
                << temp_file_path.value();
    return false;
  }

  if (!base::ReplaceFile(temp_file_path, filepath_, nullptr)) {
    PLOG(ERROR) << "Failed replacing existing hosts file with our temp file";
    return false;
  }

  return true;
}

}  // namespace crosdns
