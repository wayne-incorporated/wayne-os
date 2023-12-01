// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_dns_client.h"

#include "shill/net/ip_address.h"

namespace shill {

MockDnsClient::MockDnsClient()
    : DnsClient(IPAddress::kFamilyIPv4, "", 0, nullptr, ClientCallback()) {}

MockDnsClient::~MockDnsClient() = default;

}  // namespace shill
