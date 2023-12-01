// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/dns/dns_query.h"

#include <iterator>
#include <tuple>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

#include "patchpanel/dns/dns_protocol.h"
#include "patchpanel/dns/dns_util.h"
#include "patchpanel/dns/io_buffer.h"

namespace patchpanel {

namespace {

using ::testing::ElementsAreArray;

bool ParseAndCreateDnsQueryFromRawPacket(const uint8_t* data,
                                         size_t length,
                                         std::unique_ptr<DnsQuery>* out) {
  auto packet = base::MakeRefCounted<IOBufferWithSize>(length);
  memcpy(packet->data(), data, length);
  out->reset(new DnsQuery(packet));
  return (*out)->Parse(length);
}

// This includes \0 at the end.
const char kQNameData[] =
    "\x03"
    "www"
    "\x07"
    "example"
    "\x03"
    "com";

TEST(DnsQueryParseTest, SingleQuestionForTypeARecord) {
  const uint8_t query_data[] = {
      0x12, 0x34,  // ID
      0x00, 0x00,  // flags
      0x00, 0x01,  // number of questions
      0x00, 0x00,  // number of answer rr
      0x00, 0x00,  // number of name server rr
      0x00, 0x00,  // number of additional rr
      0x03, 'w',  'w', 'w', 0x07, 'e', 'x', 'a',
      'm',  'p',  'l', 'e', 0x03, 'c', 'o', 'm',
      0x00,        // null label
      0x00, 0x01,  // type A Record
      0x00, 0x01,  // class IN
  };
  std::unique_ptr<DnsQuery> query;
  EXPECT_TRUE(ParseAndCreateDnsQueryFromRawPacket(query_data,
                                                  sizeof(query_data), &query));
  EXPECT_EQ(0x1234, query->id());
  base::StringPiece qname(kQNameData, sizeof(kQNameData));
  EXPECT_EQ(qname, query->qname());
  EXPECT_EQ(dns_protocol::kTypeA, query->qtype());
}

TEST(DnsQueryParseTest, SingleQuestionForTypeAAAARecord) {
  const uint8_t query_data[] = {
      0x12, 0x34,  // ID
      0x00, 0x00,  // flags
      0x00, 0x01,  // number of questions
      0x00, 0x00,  // number of answer rr
      0x00, 0x00,  // number of name server rr
      0x00, 0x00,  // number of additional rr
      0x03, 'w',  'w', 'w', 0x07, 'e', 'x', 'a',
      'm',  'p',  'l', 'e', 0x03, 'c', 'o', 'm',
      0x00,        // null label
      0x00, 0x1c,  // type AAAA Record
      0x00, 0x01,  // class IN
  };
  std::unique_ptr<DnsQuery> query;
  EXPECT_TRUE(ParseAndCreateDnsQueryFromRawPacket(query_data,
                                                  sizeof(query_data), &query));
  EXPECT_EQ(0x1234, query->id());
  base::StringPiece qname(kQNameData, sizeof(kQNameData));
  EXPECT_EQ(qname, query->qname());
  EXPECT_EQ(dns_protocol::kTypeAAAA, query->qtype());
}

const uint8_t kQueryTruncatedQuestion[] = {
    0x12, 0x34,  // ID
    0x00, 0x00,  // flags
    0x00, 0x02,  // number of questions
    0x00, 0x00,  // number of answer rr
    0x00, 0x00,  // number of name server rr
    0x00, 0x00,  // number of additional rr
    0x03, 'w',  'w', 'w', 0x07, 'e', 'x', 'a',
    'm',  'p',  'l', 'e', 0x03, 'c', 'o', 'm',
    0x00,        // null label
    0x00, 0x01,  // type A Record
    0x00,        // class IN, truncated
};

const uint8_t kQueryTwoQuestions[] = {
    0x12, 0x34,  // ID
    0x00, 0x00,  // flags
    0x00, 0x02,  // number of questions
    0x00, 0x00,  // number of answer rr
    0x00, 0x00,  // number of name server rr
    0x00, 0x00,  // number of additional rr
    0x03, 'w',  'w', 'w', 0x07, 'e', 'x', 'a', 'm',  'p', 'l', 'e',
    0x03, 'c',  'o', 'm',
    0x00,        // null label
    0x00, 0x01,  // type A Record
    0x00, 0x01,  // class IN
    0x07, 'e',  'x', 'a', 'm',  'p', 'l', 'e', 0x03, 'o', 'r', 'g',
    0x00,        // null label
    0x00, 0x1c,  // type AAAA Record
    0x00, 0x01,  // class IN
};

const uint8_t kQueryInvalidDNSDomainName1[] = {
    0x12, 0x34,            // ID
    0x00, 0x00,            // flags
    0x00, 0x01,            // number of questions
    0x00, 0x00,            // number of answer rr
    0x00, 0x00,            // number of name server rr
    0x00, 0x00,            // number of additional rr
    0x02, 'w',  'w', 'w',  // wrong label length
    0x07, 'e',  'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm',
    0x00,        // null label
    0x00, 0x01,  // type A Record
    0x00, 0x01,  // class IN
};

const uint8_t kQueryInvalidDNSDomainName2[] = {
    0x12, 0x34,  // ID
    0x00, 0x00,  // flags
    0x00, 0x01,  // number of questions
    0x00, 0x00,  // number of answer rr
    0x00, 0x00,  // number of name server rr
    0x00, 0x00,  // number of additional rr
    0xc0, 0x02,  // illegal name pointer
    0x00, 0x01,  // type A Record
    0x00, 0x01,  // class IN
};

TEST(DnsQueryParseTest, FailsInvalidQueries) {
  const struct TestCase {
    const uint8_t* data;
    size_t size;
  } testcases[] = {
      {kQueryTruncatedQuestion, std::size(kQueryTruncatedQuestion)},
      {kQueryTwoQuestions, std::size(kQueryTwoQuestions)},
      {kQueryInvalidDNSDomainName1, std::size(kQueryInvalidDNSDomainName1)},
      {kQueryInvalidDNSDomainName2, std::size(kQueryInvalidDNSDomainName2)}};
  std::unique_ptr<DnsQuery> query;
  for (const auto& testcase : testcases) {
    EXPECT_FALSE(ParseAndCreateDnsQueryFromRawPacket(testcase.data,
                                                     testcase.size, &query));
  }
}

}  // namespace

}  // namespace patchpanel
