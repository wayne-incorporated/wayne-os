// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/routing_service.h"

#include <algorithm>
#include <memory>
#include <sstream>

#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

namespace patchpanel {
namespace {

auto& BYPASS_VPN = patchpanel::SetVpnIntentRequest::BYPASS_VPN;
auto& DEFAULT_ROUTING = patchpanel::SetVpnIntentRequest::DEFAULT_ROUTING;
auto& ROUTE_ON_VPN = patchpanel::SetVpnIntentRequest::ROUTE_ON_VPN;

std::string hex(uint32_t val) {
  return base::StringPrintf("0x%08x", val);
}

struct sockopt_data {
  int sockfd;
  int level;
  int optname;
  char optval[256];
  socklen_t optlen;
};

void SetOptval(sockopt_data* sockopt, uint32_t optval) {
  sockopt->optlen = sizeof(optval);
  memcpy(sockopt->optval, &optval, sizeof(optval));
}

uint32_t GetOptval(const sockopt_data& sockopt) {
  uint32_t optval;
  memcpy(&optval, sockopt.optval, sizeof(optval));
  return optval;
}

Fwmark fwmark(uint32_t fwmark) {
  return {.fwmark = fwmark};
}

class TestableRoutingService : public RoutingService {
 public:
  TestableRoutingService() = default;
  ~TestableRoutingService() = default;

  int GetSockopt(int sockfd,
                 int level,
                 int optname,
                 void* optval,
                 socklen_t* optlen) override {
    sockopt.sockfd = sockfd;
    sockopt.level = level;
    sockopt.optname = optname;
    memcpy(optval, sockopt.optval,
           std::min(*optlen, (socklen_t)sizeof(sockopt.optval)));
    *optlen = sockopt.optlen;
    return getsockopt_ret;
  }

  int SetSockopt(int sockfd,
                 int level,
                 int optname,
                 const void* optval,
                 socklen_t optlen) override {
    sockopt.sockfd = sockfd;
    sockopt.level = level;
    sockopt.optname = optname;
    sockopt.optlen = optlen;
    memcpy(sockopt.optval, optval,
           std::min(optlen, (socklen_t)sizeof(sockopt.optval)));
    return setsockopt_ret;
  }

  // Variables used to mock and track interactions with getsockopt and
  // setsockopt.
  int getsockopt_ret;
  int setsockopt_ret;
  sockopt_data sockopt;
};

class RoutingServiceTest : public testing::Test {
 public:
  RoutingServiceTest() = default;

 protected:
  void SetUp() override {}
};

}  // namespace

TEST_F(RoutingServiceTest, FwmarkSize) {
  EXPECT_EQ(sizeof(uint32_t), sizeof(Fwmark));
}

TEST_F(RoutingServiceTest, FwmarkOperators) {
  EXPECT_EQ(fwmark(0x00000000), fwmark(0x00000000) | fwmark(0x00000000));
  EXPECT_EQ(fwmark(0x00000000), fwmark(0x00000000) & fwmark(0x00000000));
  EXPECT_EQ(fwmark(0x00110034), fwmark(0x00110034) | fwmark(0x00000000));
  EXPECT_EQ(fwmark(0x00000000), fwmark(0x00110034) & fwmark(0x00000000));
  EXPECT_EQ(fwmark(0x1234abcd), fwmark(0x12340000) | fwmark(0x0000abcd));
  EXPECT_EQ(fwmark(0x00000000), fwmark(0x12340000) & fwmark(0x0000abcd));
  EXPECT_EQ(fwmark(0x00120000), fwmark(0x00120000) & fwmark(0x00120000));
  EXPECT_EQ(fwmark(0x12fffbcd), fwmark(0x1234abcd) | fwmark(0x00fff000));
  EXPECT_EQ(fwmark(0x0034a000), fwmark(0x1234abcd) & fwmark(0x00fff000));
  EXPECT_EQ(fwmark(0x0000ffff), ~fwmark(0xffff0000));
  EXPECT_EQ(fwmark(0x12345678), ~~fwmark(0x12345678));
  EXPECT_EQ(fwmark(0x55443322), ~fwmark(0xaabbccdd));
}

TEST_F(RoutingServiceTest, FwmarkAndMaskConstants) {
  EXPECT_EQ("0x00003f00", kFwmarkAllSourcesMask.ToString());
  EXPECT_EQ("0xffff0000", kFwmarkRoutingMask.ToString());
  EXPECT_EQ("0x00000001", kFwmarkLegacySNAT.ToString());
  EXPECT_EQ("0x0000c000", kFwmarkVpnMask.ToString());
  EXPECT_EQ("0x00008000", kFwmarkRouteOnVpn.ToString());
  EXPECT_EQ("0x00004000", kFwmarkBypassVpn.ToString());
  EXPECT_EQ("0x00002000", kFwmarkForwardedSourcesMask.ToString());

  EXPECT_EQ(0x00003f00, kFwmarkAllSourcesMask.Value());
  EXPECT_EQ(0xffff0000, kFwmarkRoutingMask.Value());
  EXPECT_EQ(0x00000001, kFwmarkLegacySNAT.Value());
  EXPECT_EQ(0x0000c000, kFwmarkVpnMask.Value());
  EXPECT_EQ(0x00008000, kFwmarkRouteOnVpn.Value());
  EXPECT_EQ(0x00004000, kFwmarkBypassVpn.Value());
  EXPECT_EQ(0x00002000, kFwmarkForwardedSourcesMask.Value());
}

TEST_F(RoutingServiceTest, FwmarkSources) {
  EXPECT_EQ("0x00000000",
            Fwmark::FromSource(TrafficSource::kUnknown).ToString());
  EXPECT_EQ("0x00000100",
            Fwmark::FromSource(TrafficSource::kChrome).ToString());
  EXPECT_EQ("0x00000200", Fwmark::FromSource(TrafficSource::kUser).ToString());
  EXPECT_EQ("0x00000300",
            Fwmark::FromSource(TrafficSource::kUpdateEngine).ToString());
  EXPECT_EQ("0x00000400",
            Fwmark::FromSource(TrafficSource::kSystem).ToString());
  EXPECT_EQ("0x00000500",
            Fwmark::FromSource(TrafficSource::kHostVpn).ToString());
  EXPECT_EQ("0x00002000", Fwmark::FromSource(TrafficSource::kArc).ToString());
  EXPECT_EQ("0x00002100",
            Fwmark::FromSource(TrafficSource::kCrosVM).ToString());
  EXPECT_EQ("0x00002200",
            Fwmark::FromSource(TrafficSource::kParallelsVM).ToString());
  EXPECT_EQ("0x00002300",
            Fwmark::FromSource(TrafficSource::kTetherDownstream).ToString());
  EXPECT_EQ("0x00002400",
            Fwmark::FromSource(TrafficSource::kArcVpn).ToString());

  for (auto ts : kLocalSources) {
    EXPECT_EQ(
        "0x00000000",
        (Fwmark::FromSource(ts) & kFwmarkForwardedSourcesMask).ToString());
  }
  for (auto ts : kForwardedSources) {
    EXPECT_EQ(
        kFwmarkForwardedSourcesMask.ToString(),
        (Fwmark::FromSource(ts) & kFwmarkForwardedSourcesMask).ToString());
  }

  for (auto ts : kLocalSources) {
    EXPECT_EQ("0x00000000",
              (Fwmark::FromSource(ts) & ~kFwmarkAllSourcesMask).ToString());
  }
  for (auto ts : kForwardedSources) {
    EXPECT_EQ("0x00000000",
              (Fwmark::FromSource(ts) & ~kFwmarkAllSourcesMask).ToString());
  }
}

TEST_F(RoutingServiceTest, SetVpnFwmark) {
  auto svc = std::make_unique<TestableRoutingService>();
  svc->getsockopt_ret = 0;
  svc->setsockopt_ret = 0;

  struct {
    patchpanel::SetVpnIntentRequest::VpnRoutingPolicy policy;
    uint32_t initial_fwmark;
    uint32_t expected_fwmark;
  } testcases[] = {
      {ROUTE_ON_VPN, 0x0, 0x00008000},
      {BYPASS_VPN, 0x0, 0x00004000},
      {ROUTE_ON_VPN, 0x1, 0x00008001},
      {BYPASS_VPN, 0xabcd00ef, 0xabcd40ef},
      {ROUTE_ON_VPN, 0x11223344, 0x1122b344},
      {BYPASS_VPN, 0x11223344, 0x11227344},
      {ROUTE_ON_VPN, 0x00008000, 0x00008000},
      {BYPASS_VPN, 0x00004000, 0x00004000},
      {BYPASS_VPN, 0x00008000, 0x00004000},
      {ROUTE_ON_VPN, 0x00004000, 0x00008000},
      {DEFAULT_ROUTING, 0x00008000, 0x00000000},
      {DEFAULT_ROUTING, 0x00004000, 0x00000000},
  };

  for (const auto& tt : testcases) {
    SetOptval(&svc->sockopt, tt.initial_fwmark);
    EXPECT_TRUE(svc->SetVpnFwmark(4, tt.policy));
    EXPECT_EQ(4, svc->sockopt.sockfd);
    EXPECT_EQ(SOL_SOCKET, svc->sockopt.level);
    EXPECT_EQ(SO_MARK, svc->sockopt.optname);
    EXPECT_EQ(hex(tt.expected_fwmark), hex(GetOptval(svc->sockopt)));
  }

  svc->getsockopt_ret = -1;
  svc->setsockopt_ret = 0;
  EXPECT_FALSE(svc->SetVpnFwmark(4, ROUTE_ON_VPN));

  svc->getsockopt_ret = 0;
  svc->setsockopt_ret = -1;
  EXPECT_FALSE(svc->SetVpnFwmark(4, ROUTE_ON_VPN));

  svc->getsockopt_ret = 0;
  svc->setsockopt_ret = 0;
  EXPECT_FALSE(svc->SetVpnFwmark(
      4, (patchpanel::SetVpnIntentRequest::VpnRoutingPolicy)-1));
}

TEST_F(RoutingServiceTest, SetFwmark) {
  auto svc = std::make_unique<TestableRoutingService>();
  svc->getsockopt_ret = 0;
  svc->setsockopt_ret = 0;

  struct {
    uint32_t initial_fwmark;
    uint32_t fwmark_value;
    uint32_t fwmark_mask;
    uint32_t expected_fwmark;
  } testcases[] = {
      {0x0, 0x0, 0x0, 0x0},
      {0x1, 0x0, 0x0, 0x1},
      {0x1, 0x0, 0x1, 0x0},
      {0xaabbccdd, 0x11223344, 0xf0f0f0f0, 0x1a2b3c4d},
      {0xaabbccdd, 0x11223344, 0xffff0000, 0x1122ccdd},
      {0xaabbccdd, 0x11223344, 0x0000ffff, 0xaabb3344},
  };

  for (const auto& tt : testcases) {
    SetOptval(&svc->sockopt, tt.initial_fwmark);
    EXPECT_TRUE(
        svc->SetFwmark(4, fwmark(tt.fwmark_value), fwmark(tt.fwmark_mask)));
    EXPECT_EQ(4, svc->sockopt.sockfd);
    EXPECT_EQ(SOL_SOCKET, svc->sockopt.level);
    EXPECT_EQ(SO_MARK, svc->sockopt.optname);
    EXPECT_EQ(hex(tt.expected_fwmark), hex(GetOptval(svc->sockopt)));
  }
}

TEST_F(RoutingServiceTest, SetFwmark_Failures) {
  auto svc = std::make_unique<TestableRoutingService>();
  svc->getsockopt_ret = -1;
  svc->setsockopt_ret = 0;
  EXPECT_FALSE(svc->SetFwmark(4, fwmark(0x1), fwmark(0x01)));

  svc = std::make_unique<TestableRoutingService>();
  svc->getsockopt_ret = 0;
  svc->setsockopt_ret = -1;
  EXPECT_FALSE(svc->SetFwmark(5, fwmark(0x1), fwmark(0x01)));

  svc = std::make_unique<TestableRoutingService>();
  svc->getsockopt_ret = 0;
  svc->setsockopt_ret = 0;
  EXPECT_TRUE(svc->SetFwmark(6, fwmark(0x1), fwmark(0x01)));
}

TEST_F(RoutingServiceTest, LocalSourceSpecsPrettyPrinting) {
  struct {
    LocalSourceSpecs source;
    std::string expected_output;
  } testcases[] = {
      {{}, "{source: UNKNOWN, uid: , classid: 0, is_on_vpn: false}"},
      {{TrafficSource::kChrome, kUidChronos, 0, true},
       "{source: CHROME, uid: chronos, classid: 0, is_on_vpn: true}"},
      {{TrafficSource::kUser, kUidDebugd, 0, true},
       "{source: USER, uid: debugd, classid: 0, is_on_vpn: true}"},
      {{TrafficSource::kSystem, kUidTlsdate, 0, true},
       "{source: SYSTEM, uid: tlsdate, classid: 0, is_on_vpn: true}"},
      {{TrafficSource::kUser, kUidPluginvm, 0, true},
       "{source: USER, uid: pluginvm, classid: 0, is_on_vpn: true}"},
      {{TrafficSource::kUpdateEngine, "", 1234, false},
       "{source: UPDATE_ENGINE, uid: , classid: 1234, is_on_vpn: false}"},
  };

  for (const auto& tt : testcases) {
    std::ostringstream stream;
    stream << tt.source;
    EXPECT_EQ(tt.expected_output, stream.str());
  }
}

}  // namespace patchpanel
