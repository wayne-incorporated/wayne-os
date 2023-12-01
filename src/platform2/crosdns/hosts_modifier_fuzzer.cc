// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crosdns/hosts_modifier.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include <base/check.h>
#include <base/files/scoped_temp_dir.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>

constexpr char kBaseFileContents[] =
    "# Example /etc/hosts file\n"
    "127.0.0.1 localhost\n";
constexpr char kValidIpPrefix[] = "100.115.92.";
constexpr char kValidHostnameSuffix[] = ".linux.test";

struct Environment {
  Environment() {
    CHECK(temp_dir.CreateUniqueTempDir());
    base::FilePath hosts_file = temp_dir.GetPath().Append("hosts");
    base::WriteFile(hosts_file, kBaseFileContents, strlen(kBaseFileContents));
    hosts_modifier.Init(hosts_file);
  }

  base::ScopedTempDir temp_dir;
  crosdns::HostsModifier hosts_modifier;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);
  // The aspects that we randomize based on the fuzzed data for better coverage
  // are:
  // - Using a valid numerical IP address (i.e. x.x.x.x where x < 256)
  // - Using an IP address in our allowed range of 100.115.92.x
  // - Using a valid hostname suffix of .linux.test
  // - Using the same hostname for remove as add vs. a fuzzed hostname
  std::string ip;
  bool useNumericIp = data_provider.ConsumeBool();
  if (useNumericIp) {
    bool useValidIpRange = data_provider.ConsumeBool();
    if (useValidIpRange) {
      ip = kValidIpPrefix;
      ip.append(base::NumberToString(data_provider.ConsumeIntegral<uint8_t>()));
    } else {
      ip =
          base::NumberToString(data_provider.ConsumeIntegral<uint8_t>()) + "." +
          base::NumberToString(data_provider.ConsumeIntegral<uint8_t>()) + "." +
          base::NumberToString(data_provider.ConsumeIntegral<uint8_t>()) + "." +
          base::NumberToString(data_provider.ConsumeIntegral<uint8_t>());
    }
  } else {
    // We will want up to 3 strings, so take a random length of 1/3 the total
    // length.
    ip = data_provider.ConsumeRandomLengthString(size / 3);
  }
  std::string hostname;
  bool useValidHostnameSuffix = data_provider.ConsumeBool();
  if (useValidHostnameSuffix) {
    hostname = data_provider.ConsumeRandomLengthString(size / 3) +
               kValidHostnameSuffix;
  } else {
    hostname = data_provider.ConsumeRandomLengthString(size / 3);
  }
  std::string err;
  // Use the empty string for IPv6 since we don't do anything with that arg yet.
  env.hosts_modifier.SetHostnameIpMapping(hostname, ip, "", &err);

  bool removeSameHostnameAdded = data_provider.ConsumeBool();
  if (removeSameHostnameAdded) {
    env.hosts_modifier.RemoveHostnameIpMapping(hostname, &err);
  } else {
    env.hosts_modifier.RemoveHostnameIpMapping(
        data_provider.ConsumeRandomLengthString(size / 3), &err);
  }
  return 0;
}
