// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include <gtest/gtest.h>

#include "smbprovider/netbios_packet_parser.h"
#include "smbprovider/smbprovider_test_helper.h"

namespace smbprovider {
namespace {

constexpr int kNonFileServerNodeType = 0x00;

const std::vector<uint8_t> CreateName(const std::string& name) {
  return std::vector<uint8_t>(name.begin(), name.end());
}

}  // namespace

class NetBiosPacketParserTest : public testing::Test {
 public:
  NetBiosPacketParserTest() = default;
  NetBiosPacketParserTest(const NetBiosPacketParserTest&) = delete;
  NetBiosPacketParserTest& operator=(const NetBiosPacketParserTest&) = delete;

  ~NetBiosPacketParserTest() override = default;

 protected:
  const uint16_t transaction_id_ = 123;
};

// An empty packet returns no results.
TEST_F(NetBiosPacketParserTest, EmptyPacketReturnsNoResults) {
  const std::vector<uint8_t> packet;

  const std::vector<std::string> results =
      netbios::ParsePacket(packet, transaction_id_);

  EXPECT_TRUE(results.empty());
}

// A well-formed packet with no hostnames returns no results.
TEST_F(NetBiosPacketParserTest, NoHostnamesReturnsNoResults) {
  const std::vector<uint8_t> name = CreateName("testname");
  const std::vector<std::vector<uint8_t>> hostnames;

  const std::vector<uint8_t> packet = CreateNetBiosResponsePacket(
      hostnames, name, transaction_id_, 0x20 /* positive response */);

  const std::vector<std::string> results =
      netbios::ParsePacket(packet, transaction_id_);

  EXPECT_TRUE(results.empty());
}

// A well-formed packet with one hostname parses successfully.
TEST_F(NetBiosPacketParserTest, OneHostnameSucceeds) {
  const std::vector<uint8_t> name = CreateName("testname");
  const std::string hostname_1 = "hostname1";
  const std::vector<std::vector<uint8_t>> hostnames = {
      CreateValidNetBiosHostname(hostname_1, netbios::kFileServerNodeType)};

  const std::vector<uint8_t> packet = CreateNetBiosResponsePacket(
      hostnames, name, transaction_id_, 0x20 /* positive response */);

  const std::vector<std::string> results =
      netbios::ParsePacket(packet, transaction_id_);

  EXPECT_EQ(1, results.size());
  EXPECT_EQ(hostname_1, results[0]);
}

// A well-formed packet with two hostnames parses successfully.
TEST_F(NetBiosPacketParserTest, TwoHostnamesSucceeds) {
  const std::vector<uint8_t> name = CreateName("testname");
  const std::string hostname_1 = "hostname1";
  const std::string hostname_2 = "hostname2";
  const std::vector<std::vector<uint8_t>> hostnames = {
      CreateValidNetBiosHostname(hostname_1, netbios::kFileServerNodeType),
      CreateValidNetBiosHostname(hostname_2, netbios::kFileServerNodeType)};

  const std::vector<uint8_t> packet = CreateNetBiosResponsePacket(
      hostnames, name, transaction_id_, 0x20 /* positive response */);

  const std::vector<std::string> results =
      netbios::ParsePacket(packet, transaction_id_);

  EXPECT_EQ(2, results.size());
  EXPECT_EQ(hostname_1, results[0]);
  EXPECT_EQ(hostname_2, results[1]);
}

// The parser does not return non-FileServer hostnames.
TEST_F(NetBiosPacketParserTest, NonShareDoesntReturn) {
  const std::vector<uint8_t> name = CreateName("testname");
  const std::string hostname_1 = "hostname1";
  const std::string hostname_2 = "hostname2";
  const std::vector<std::vector<uint8_t>> hostnames = {
      CreateValidNetBiosHostname(hostname_1, kNonFileServerNodeType),
      CreateValidNetBiosHostname(hostname_2, netbios::kFileServerNodeType)};

  const std::vector<uint8_t> packet = CreateNetBiosResponsePacket(
      hostnames, name, transaction_id_, 0x20 /* positive response */);

  const std::vector<std::string> results =
      netbios::ParsePacket(packet, transaction_id_);

  EXPECT_EQ(1, results.size());
  EXPECT_EQ(hostname_2, results[0]);
}

// A well-formed negative response returns no results.
TEST_F(NetBiosPacketParserTest, NegativeResponseFails) {
  const std::vector<uint8_t> name = CreateName("testname");
  const std::string hostname_1 = "hostname1";
  const std::vector<std::vector<uint8_t>> hostnames = {
      CreateValidNetBiosHostname(hostname_1, netbios::kFileServerNodeType)};

  const std::vector<uint8_t> packet = CreateNetBiosResponsePacket(
      hostnames, name, transaction_id_, 0x00 /* negative response */);

  const std::vector<std::string> results =
      netbios::ParsePacket(packet, transaction_id_);

  EXPECT_TRUE(results.empty());
}

// A mal-formed packet with a name that is too long returns no results.
TEST_F(NetBiosPacketParserTest, NameTooLongFails) {
  const std::vector<uint8_t> name = CreateName("testname");
  const uint8_t name_length(150);
  const std::string hostname_1 = "hostname1";
  const std::vector<std::vector<uint8_t>> hostnames = {
      CreateValidNetBiosHostname(hostname_1, netbios::kFileServerNodeType)};

  const std::vector<uint8_t> packet =
      CreateNetBiosResponsePacket(hostnames, name_length, name, transaction_id_,
                                  0x20 /* positive response */);

  const std::vector<std::string> results =
      netbios::ParsePacket(packet, transaction_id_);

  EXPECT_TRUE(results.empty());
}

// A mal-formed packet with incorrectly formed hostnames returns no results.
TEST_F(NetBiosPacketParserTest, MalformedHostnamesFails) {
  const std::vector<uint8_t> name = CreateName("testname");
  const std::string bad_hostname = "tooooooolonggggghostnameeee";
  const std::vector<std::vector<uint8_t>> hostnames = {
      std::vector<uint8_t>(bad_hostname.begin(), bad_hostname.end())};

  const std::vector<uint8_t> packet = CreateNetBiosResponsePacket(
      hostnames, name, transaction_id_, 0x20 /* positive response */);

  const std::vector<std::string> results =
      netbios::ParsePacket(packet, transaction_id_);

  EXPECT_TRUE(results.empty());
}

// A well-formed packet with the transaction id that does not correspond to the
// broadcast returns no results.
TEST_F(NetBiosPacketParserTest, TestName) {
  const std::vector<uint8_t> name = CreateName("testname");
  const std::string hostname_1 = "hostname1";
  const std::vector<std::vector<uint8_t>> hostnames = {
      CreateValidNetBiosHostname(hostname_1, netbios::kFileServerNodeType)};

  const std::vector<uint8_t> packet = CreateNetBiosResponsePacket(
      hostnames, name, transaction_id_, 0x20 /* positive response */);

  const std::vector<std::string> results =
      netbios::ParsePacket(packet, transaction_id_ + 1);

  EXPECT_TRUE(results.empty());
}

// A positive response with the NBSTAT signal (0x21) instead of NB (0x20)
// returns a result correctly.
TEST_F(NetBiosPacketParserTest, AlternatePositiveResponseSucceeds) {
  const std::vector<uint8_t> name = CreateName("testname");
  const std::string hostname_1 = "hostname1";
  const std::vector<std::vector<uint8_t>> hostnames = {
      CreateValidNetBiosHostname(hostname_1, netbios::kFileServerNodeType)};

  const std::vector<uint8_t> packet = CreateNetBiosResponsePacket(
      hostnames, name, transaction_id_, 0x21 /* positive response */);

  const std::vector<std::string> results =
      netbios::ParsePacket(packet, transaction_id_);

  EXPECT_EQ(1, results.size());
  EXPECT_EQ(hostname_1, results[0]);
}

}  // namespace smbprovider
