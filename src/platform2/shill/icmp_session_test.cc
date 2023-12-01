// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/icmp_session.h"

#include <base/test/simple_test_tick_clock.h>
#include <gtest/gtest.h>

#include "shill/mock_event_dispatcher.h"
#include "shill/mock_icmp.h"
#include "shill/net/ip_address.h"
#include "shill/net/mock_io_handler_factory.h"

using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::StrictMock;
using testing::Test;

namespace shill {

namespace {

// Note: this IPv4 header is given in network byte order, since
// IcmpSession::OnEchoReplyReceived expects to receive a raw IP packet.
const uint8_t kIpHeader[] = {0x45, 0x80, 0x00, 0x1c, 0x63, 0xd3, 0x00,
                             0x00, 0x39, 0x01, 0xcc, 0x9f, 0x4a, 0x7d,
                             0xe0, 0x18, 0x64, 0x6e, 0xc1, 0xea};
// ICMPv4 echo replies with 0 bytes of data and and echo ID 0. Sequence numbers
// are 0x8, 0x9, and 0xa respectively to simulate replies to a sequence of sent
// echo requests.  Note that these only match on little-endian hosts.
const uint8_t kIcmpEchoReply1[] = {0x00, 0x00, 0xf7, 0xff,
                                   0x00, 0x00, 0x08, 0x00};
const uint16_t kIcmpEchoReply1_SeqNum = 0x08;
const uint8_t kIcmpEchoReply2[] = {0x00, 0x00, 0xf6, 0xff,
                                   0x00, 0x00, 0x09, 0x00};
const uint16_t kIcmpEchoReply2_SeqNum = 0x09;
const uint8_t kIcmpEchoReply3[] = {0x00, 0x00, 0xf5, 0xff,
                                   0x00, 0x00, 0x0a, 0x00};
const uint16_t kIcmpEchoReply3_SeqNum = 0x0a;

// ICMPv6 echo reply with 0 bytes of data, echo ID 0, and sequence number 0x8.
const uint8_t kIcmpV6EchoReply1[] = {0x81, 0x00, 0x76, 0xff,
                                     0x00, 0x00, 0x08, 0x00};

// This ICMPv4 echo reply has an echo ID of 0xe, which is different from the
// echo ID used in the unit tests (0).
const uint8_t kIcmpEchoReplyDifferentEchoID[] = {0x00, 0x00, 0xea, 0xff,
                                                 0x0e, 0x00, 0x0b, 0x00};

}  // namespace

class IcmpSessionTest : public Test {
 public:
  IcmpSessionTest() : icmp_session_(&dispatcher_) {}
  ~IcmpSessionTest() override = default;

  void SetUp() override {
    icmp_session_.io_handler_factory_ = &io_handler_factory_;
    icmp_session_.tick_clock_ = &testing_clock_;
    icmp_ = new NiceMock<MockIcmp>();
    // Passes ownership.
    icmp_session_.icmp_.reset(icmp_);
    ON_CALL(*icmp_, IsStarted()).WillByDefault(Return(false));
  }

  void TearDown() override {
    EXPECT_CALL(*icmp_, IsStarted());
    IcmpSession::kNextUniqueEchoId = 0;
  }

  MOCK_METHOD(void, ResultCallback, (const IcmpSession::IcmpSessionResult&));

 protected:
  static const char kIPAddress[];
  static const char kIP6Address[];
  static const int kInterfaceIndex;

  void StartAndVerify(const IPAddress& destination, int interface_index) {
    EXPECT_CALL(*icmp_, IsStarted());
    EXPECT_CALL(*icmp_, Start(destination, interface_index))
        .WillOnce(Return(true));
    icmp_->destination_ = destination;
    EXPECT_CALL(io_handler_factory_,
                CreateIOInputHandler(icmp_->socket(), _, _));
    EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, GetTimeout()));
    EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    EXPECT_TRUE(Start(destination, interface_index));
    EXPECT_TRUE(GetSeqNumToSentRecvTime()->empty());
    EXPECT_TRUE(GetReceivedEchoReplySeqNumbers()->empty());
    EXPECT_CALL(*icmp_, IsStarted()).WillRepeatedly(Return(true));
  }

  bool Start(const IPAddress& destination, int interface_index) {
    return icmp_session_.Start(destination, interface_index,
                               base::BindOnce(&IcmpSessionTest::ResultCallback,
                                              base::Unretained(this)));
  }

  void Stop() { icmp_session_.Stop(); }

  bool SeqNumToSentRecvTimeContains(uint16_t seq_num) {
    return icmp_session_.seq_num_to_sent_recv_time_.find(seq_num) !=
           icmp_session_.seq_num_to_sent_recv_time_.end();
  }

  bool ReceivedEchoReplySeqNumbersContains(uint16_t seq_num) {
    return icmp_session_.received_echo_reply_seq_numbers_.find(seq_num) !=
           icmp_session_.received_echo_reply_seq_numbers_.end();
  }

  void TransmitEchoRequestTask(bool transmit_request_success) {
    EXPECT_CALL(*icmp_, TransmitEchoRequest(icmp_session_.echo_id_,
                                            GetCurrentSequenceNumber()))
        .WillOnce(Return(transmit_request_success));
    icmp_session_.TransmitEchoRequestTask();
  }

  void ReportResultAndStopSession() {
    icmp_session_.ReportResultAndStopSession();
  }

  void VerifyIcmpSessionStopped() {
    EXPECT_TRUE(icmp_session_.timeout_callback_.IsCancelled());
    EXPECT_FALSE(icmp_session_.echo_reply_handler_);
  }

  void OnEchoReplyReceived(InputData* data) {
    icmp_session_.OnEchoReplyReceived(data);
  }

  IcmpSession::IcmpSessionResult GenerateIcmpResult() {
    return icmp_session_.GenerateIcmpResult();
  }

  std::map<uint16_t, IcmpSession::SentRecvTimePair>* GetSeqNumToSentRecvTime() {
    return &icmp_session_.seq_num_to_sent_recv_time_;
  }
  std::set<uint16_t>* GetReceivedEchoReplySeqNumbers() {
    return &icmp_session_.received_echo_reply_seq_numbers_;
  }
  uint16_t GetNextUniqueEchoId() const {
    return IcmpSession::kNextUniqueEchoId;
  }
  int GetTotalNumEchoRequests() const {
    return IcmpSession::kTotalNumEchoRequests;
  }
  int GetCurrentSequenceNumber() const {
    return icmp_session_.current_sequence_number_;
  }
  void SetCurrentSequenceNumber(uint16_t val) {
    icmp_session_.current_sequence_number_ = val;
  }
  base::TimeDelta GetTimeout() const { return IcmpSession::kTimeout; }
  base::TimeDelta GetEchoRequestInterval() const {
    return IcmpSession::kEchoRequestInterval;
  }

  MockIcmp* icmp_;
  MockIOHandlerFactory io_handler_factory_;
  StrictMock<MockEventDispatcher> dispatcher_;
  IcmpSession icmp_session_;
  base::SimpleTestTickClock testing_clock_;
};

const char IcmpSessionTest::kIPAddress[] = "10.0.1.1";
const char IcmpSessionTest::kIP6Address[] = "2001:db8::1234:5678";
const int IcmpSessionTest::kInterfaceIndex = 3;

TEST_F(IcmpSessionTest, Constructor) {
  // |icmp_session_| should have been assigned the value of |kNextUniqueEchoId|
  // on construction, and caused the value of this static variable to be
  // incremented.
  uint16_t saved_echo_id = GetNextUniqueEchoId();
  EXPECT_EQ(saved_echo_id - 1, icmp_session_.echo_id_);

  // The next IcmpSession object constructed, |session| should get the next
  // unique value of |kNextUniqueEchoId|, and further increment this variable.
  IcmpSession session(&dispatcher_);
  EXPECT_EQ(saved_echo_id, session.echo_id_);
  EXPECT_EQ(saved_echo_id + 1, GetNextUniqueEchoId());
}

TEST_F(IcmpSessionTest, StartWhileAlreadyStarted) {
  const auto ipv4_destination = IPAddress::CreateFromString(kIPAddress);
  CHECK(ipv4_destination.has_value());
  StartAndVerify(*ipv4_destination, kInterfaceIndex);

  // Since an ICMP session is already started, we should fail to start it again.
  EXPECT_CALL(*icmp_, Start(*ipv4_destination, kInterfaceIndex)).Times(0);
  EXPECT_CALL(io_handler_factory_, CreateIOInputHandler(_, _, _)).Times(0);
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, _)).Times(0);
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta())).Times(0);
  EXPECT_FALSE(Start(*ipv4_destination, kInterfaceIndex));
}

TEST_F(IcmpSessionTest, StopWhileNotStarted) {
  // Attempting to stop the ICMP session while it is not started should do
  // nothing.
  EXPECT_CALL(*icmp_, IsStarted()).WillOnce(Return(false));
  EXPECT_CALL(*this, ResultCallback(_)).Times(0);
  EXPECT_CALL(*icmp_, Stop()).Times(0);
  Stop();
}

TEST_F(IcmpSessionTest, SessionSuccess) {
  // Test a successful ICMP session where the sending of requests and receiving
  // of replies are interleaved. Moreover, test the case where transmitting an
  // echo request fails.

  base::TimeTicks now = testing_clock_.NowTicks();
  base::TimeTicks kSentTime1 = base::TimeTicks::FromInternalValue(10);
  base::TimeTicks kRecvTime1 = base::TimeTicks::FromInternalValue(20);
  base::TimeTicks kSentTime2 = base::TimeTicks::FromInternalValue(30);
  base::TimeTicks kSentTime3 = base::TimeTicks::FromInternalValue(40);
  base::TimeTicks kRecvTime2 = base::TimeTicks::FromInternalValue(50);
  base::TimeTicks kWrongEchoIDRecvTime = base::TimeTicks::FromInternalValue(60);
  base::TimeTicks kRecvTime3 = base::TimeTicks::FromInternalValue(70);

  IcmpSession::IcmpSessionResult expected_result = {
      kRecvTime1 - kSentTime1,
      kRecvTime2 - kSentTime2,
      kRecvTime3 - kSentTime3,
  };

  // Initiate session.
  const auto ipv4_destination = IPAddress::CreateFromString(kIPAddress);
  CHECK(ipv4_destination.has_value());
  StartAndVerify(*ipv4_destination, kInterfaceIndex);

  // Send the first echo request.
  testing_clock_.Advance(kSentTime1 - now);
  now = testing_clock_.NowTicks();
  SetCurrentSequenceNumber(kIcmpEchoReply1_SeqNum);
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, GetEchoRequestInterval()));
  TransmitEchoRequestTask(true);
  EXPECT_TRUE(GetReceivedEchoReplySeqNumbers()->empty());
  EXPECT_EQ(1, GetSeqNumToSentRecvTime()->size());
  EXPECT_TRUE(SeqNumToSentRecvTimeContains(kIcmpEchoReply1_SeqNum));
  EXPECT_EQ(now, GetSeqNumToSentRecvTime()->at(kIcmpEchoReply1_SeqNum).first);
  EXPECT_EQ(kIcmpEchoReply2_SeqNum, GetCurrentSequenceNumber());

  // Receive first reply.
  testing_clock_.Advance(kRecvTime1 - now);
  now = testing_clock_.NowTicks();
  uint8_t buffer_1[sizeof(kIpHeader) + sizeof(kIcmpEchoReply1)];
  memcpy(buffer_1, kIpHeader, sizeof(kIpHeader));
  memcpy(buffer_1 + sizeof(kIpHeader), kIcmpEchoReply1,
         sizeof(kIcmpEchoReply1));
  InputData data_1(reinterpret_cast<unsigned char*>(buffer_1),
                   sizeof(buffer_1));
  EXPECT_CALL(*this, ResultCallback(_)).Times(0);
  OnEchoReplyReceived(&data_1);
  EXPECT_EQ(1, GetReceivedEchoReplySeqNumbers()->size());
  EXPECT_TRUE(ReceivedEchoReplySeqNumbersContains(kIcmpEchoReply1_SeqNum));

  // Send the second echo request.
  testing_clock_.Advance(kSentTime2 - now);
  now = testing_clock_.NowTicks();
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, GetEchoRequestInterval()));
  TransmitEchoRequestTask(true);
  EXPECT_EQ(1, GetReceivedEchoReplySeqNumbers()->size());
  EXPECT_EQ(2, GetSeqNumToSentRecvTime()->size());
  EXPECT_TRUE(SeqNumToSentRecvTimeContains(kIcmpEchoReply2_SeqNum));
  EXPECT_EQ(now, GetSeqNumToSentRecvTime()->at(kIcmpEchoReply2_SeqNum).first);
  EXPECT_EQ(kIcmpEchoReply3_SeqNum, GetCurrentSequenceNumber());

  // Sending final request.
  testing_clock_.Advance(kSentTime3 - now);
  now = testing_clock_.NowTicks();
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, _)).Times(0);
  EXPECT_CALL(*icmp_, Stop()).Times(0);
  TransmitEchoRequestTask(true);
  EXPECT_EQ(1, GetReceivedEchoReplySeqNumbers()->size());
  EXPECT_EQ(3, GetSeqNumToSentRecvTime()->size());
  EXPECT_TRUE(SeqNumToSentRecvTimeContains(kIcmpEchoReply3_SeqNum));
  EXPECT_EQ(now, GetSeqNumToSentRecvTime()->at(kIcmpEchoReply3_SeqNum).first);
  EXPECT_EQ(kIcmpEchoReply3_SeqNum + 1, GetCurrentSequenceNumber());

  // Receive second reply.
  testing_clock_.Advance(kRecvTime2 - now);
  now = testing_clock_.NowTicks();
  uint8_t buffer_2[sizeof(kIpHeader) + sizeof(kIcmpEchoReply2)];
  memcpy(buffer_2, kIpHeader, sizeof(kIpHeader));
  memcpy(buffer_2 + sizeof(kIpHeader), kIcmpEchoReply2,
         sizeof(kIcmpEchoReply2));
  InputData data_2(reinterpret_cast<unsigned char*>(buffer_2),
                   sizeof(buffer_2));
  EXPECT_CALL(*this, ResultCallback(_)).Times(0);
  EXPECT_CALL(*icmp_, Stop()).Times(0);
  OnEchoReplyReceived(&data_2);
  EXPECT_EQ(3, GetSeqNumToSentRecvTime()->size());
  EXPECT_EQ(2, GetReceivedEchoReplySeqNumbers()->size());
  EXPECT_TRUE(ReceivedEchoReplySeqNumbersContains(kIcmpEchoReply2_SeqNum));

  // Receive a reply that has an echo ID that does not match that of this
  // ICMP session. This reply will not be processed.
  testing_clock_.Advance(kWrongEchoIDRecvTime - now);
  now = testing_clock_.NowTicks();
  uint8_t buffer_3[sizeof(kIpHeader) + sizeof(kIcmpEchoReplyDifferentEchoID)];
  memcpy(buffer_3, kIpHeader, sizeof(kIpHeader));
  memcpy(buffer_3 + sizeof(kIpHeader), kIcmpEchoReplyDifferentEchoID,
         sizeof(kIcmpEchoReplyDifferentEchoID));
  InputData data_3(reinterpret_cast<unsigned char*>(buffer_3),
                   sizeof(buffer_3));
  EXPECT_CALL(*this, ResultCallback(_)).Times(0);
  EXPECT_CALL(*icmp_, Stop()).Times(0);
  OnEchoReplyReceived(&data_3);
  EXPECT_EQ(3, GetSeqNumToSentRecvTime()->size());
  EXPECT_EQ(2, GetReceivedEchoReplySeqNumbers()->size());

  // Receive third reply, which concludes the ICMP session.
  testing_clock_.Advance(kRecvTime3 - now);
  now = testing_clock_.NowTicks();
  uint8_t buffer_4[sizeof(kIpHeader) + sizeof(kIcmpEchoReply3)];
  memcpy(buffer_4, kIpHeader, sizeof(kIpHeader));
  memcpy(buffer_4 + sizeof(kIpHeader), kIcmpEchoReply3,
         sizeof(kIcmpEchoReply3));
  InputData data_4(reinterpret_cast<unsigned char*>(buffer_4),
                   sizeof(buffer_4));
  EXPECT_CALL(*this, ResultCallback(expected_result));
  EXPECT_CALL(*icmp_, Stop());
  OnEchoReplyReceived(&data_4);
  EXPECT_EQ(3, GetSeqNumToSentRecvTime()->size());
  EXPECT_EQ(3, GetReceivedEchoReplySeqNumbers()->size());
  EXPECT_TRUE(ReceivedEchoReplySeqNumbersContains(kIcmpEchoReply3_SeqNum));

  VerifyIcmpSessionStopped();
}

TEST_F(IcmpSessionTest, ICMPv6) {
  // Initiate session.
  const auto ipv6_destination = IPAddress::CreateFromString(kIP6Address);
  CHECK(ipv6_destination.has_value());
  StartAndVerify(*ipv6_destination, kInterfaceIndex);

  // Send an echo request.
  SetCurrentSequenceNumber(kIcmpEchoReply1_SeqNum);
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, GetEchoRequestInterval()));
  TransmitEchoRequestTask(true);
  EXPECT_TRUE(GetReceivedEchoReplySeqNumbers()->empty());
  EXPECT_EQ(1, GetSeqNumToSentRecvTime()->size());
  EXPECT_TRUE(SeqNumToSentRecvTimeContains(kIcmpEchoReply1_SeqNum));
  EXPECT_EQ(kIcmpEchoReply2_SeqNum, GetCurrentSequenceNumber());

  // Receive a reply.
  uint8_t buffer_1[sizeof(kIcmpV6EchoReply1)];
  memcpy(buffer_1, kIcmpV6EchoReply1, sizeof(kIcmpV6EchoReply1));
  InputData data_1(reinterpret_cast<unsigned char*>(buffer_1),
                   sizeof(buffer_1));
  EXPECT_CALL(*this, ResultCallback(_)).Times(0);
  OnEchoReplyReceived(&data_1);
  EXPECT_EQ(1, GetReceivedEchoReplySeqNumbers()->size());
  EXPECT_TRUE(ReceivedEchoReplySeqNumbersContains(kIcmpEchoReply1_SeqNum));

  EXPECT_CALL(*icmp_, Stop());
  Stop();
  VerifyIcmpSessionStopped();
}

TEST_F(IcmpSessionTest, SessionTimeoutOrInterrupted) {
  // Test a failed ICMP session where we neither send out all echo requests nor
  // receive all echo replies before stopping the ICMP session (because of a
  // timeout or a manually-triggered stop). Moreover, test that echo requests
  // that are sent unsuccessfully are sent again.

  base::TimeTicks now = testing_clock_.NowTicks();
  base::TimeTicks kSentTime1 = base::TimeTicks::FromInternalValue(10);
  base::TimeTicks kSentTime2 = base::TimeTicks::FromInternalValue(20);
  base::TimeTicks kRecvTime1 = base::TimeTicks::FromInternalValue(30);
  base::TimeTicks kResendTime1 = base::TimeTicks::FromInternalValue(40);

  IcmpSession::IcmpSessionResult expected_partial_result = {
      kRecvTime1 - kSentTime1,
      base::TimeDelta(),
  };

  // Initiate session.
  const auto ipv4_destination = IPAddress::CreateFromString(kIPAddress);
  CHECK(ipv4_destination.has_value());
  StartAndVerify(*ipv4_destination, kInterfaceIndex);

  // Send the first echo request successfully.
  testing_clock_.Advance(kSentTime1 - now);
  now = testing_clock_.NowTicks();
  SetCurrentSequenceNumber(kIcmpEchoReply1_SeqNum);
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, GetEchoRequestInterval()));
  TransmitEchoRequestTask(true);
  EXPECT_TRUE(GetReceivedEchoReplySeqNumbers()->empty());
  EXPECT_EQ(1, GetSeqNumToSentRecvTime()->size());
  EXPECT_TRUE(SeqNumToSentRecvTimeContains(kIcmpEchoReply1_SeqNum));
  EXPECT_EQ(now, GetSeqNumToSentRecvTime()->at(kIcmpEchoReply1_SeqNum).first);
  EXPECT_EQ(kIcmpEchoReply2_SeqNum, GetCurrentSequenceNumber());

  // Send the second echo request unsuccessfully.
  testing_clock_.Advance(kSentTime2 - now);
  now = testing_clock_.NowTicks();
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, GetEchoRequestInterval()));
  TransmitEchoRequestTask(false);
  EXPECT_TRUE(GetReceivedEchoReplySeqNumbers()->empty());
  EXPECT_EQ(1, GetSeqNumToSentRecvTime()->size());
  EXPECT_FALSE(SeqNumToSentRecvTimeContains(kIcmpEchoReply2_SeqNum));
  // The sequence number should still be incremented when we fail to transmit an
  // echo request.
  EXPECT_EQ(kIcmpEchoReply3_SeqNum, GetCurrentSequenceNumber());

  // Receive first reply.
  testing_clock_.Advance(kRecvTime1 - now);
  now = testing_clock_.NowTicks();
  uint8_t buffer_1[sizeof(kIpHeader) + sizeof(kIcmpEchoReply1)];
  memcpy(buffer_1, kIpHeader, sizeof(kIpHeader));
  memcpy(buffer_1 + sizeof(kIpHeader), kIcmpEchoReply1,
         sizeof(kIcmpEchoReply1));
  InputData data_1(reinterpret_cast<unsigned char*>(buffer_1),
                   sizeof(buffer_1));
  EXPECT_CALL(*this, ResultCallback(_)).Times(0);
  OnEchoReplyReceived(&data_1);
  EXPECT_EQ(1, GetReceivedEchoReplySeqNumbers()->size());
  EXPECT_TRUE(ReceivedEchoReplySeqNumbersContains(kIcmpEchoReply1_SeqNum));

  // Resend second echo request successfully.
  testing_clock_.Advance(kResendTime1 - now);
  now = testing_clock_.NowTicks();
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, GetEchoRequestInterval()));
  TransmitEchoRequestTask(true);
  EXPECT_EQ(1, GetReceivedEchoReplySeqNumbers()->size());
  EXPECT_EQ(2, GetSeqNumToSentRecvTime()->size());
  EXPECT_TRUE(SeqNumToSentRecvTimeContains(kIcmpEchoReply3_SeqNum));
  EXPECT_EQ(now, GetSeqNumToSentRecvTime()->at(kIcmpEchoReply3_SeqNum).first);
  EXPECT_EQ(kIcmpEchoReply3_SeqNum + 1, GetCurrentSequenceNumber());

  // Timeout triggered, so report partial results.
  EXPECT_CALL(*this, ResultCallback(expected_partial_result));
  EXPECT_CALL(*icmp_, Stop());
  ReportResultAndStopSession();
  EXPECT_EQ(2, GetSeqNumToSentRecvTime()->size());
  EXPECT_EQ(1, GetReceivedEchoReplySeqNumbers()->size());
  VerifyIcmpSessionStopped();
}

TEST_F(IcmpSessionTest, DoNotReportResultsOnStop) {
  // Initiate session.
  const auto ipv4_destination = IPAddress::CreateFromString(kIPAddress);
  CHECK(ipv4_destination.has_value());
  StartAndVerify(*ipv4_destination, kInterfaceIndex);

  // Session interrupted manually by calling Stop(), so do not report results.
  EXPECT_CALL(*this, ResultCallback(_)).Times(0);
  EXPECT_CALL(*icmp_, Stop());
  Stop();
  VerifyIcmpSessionStopped();
}

TEST_F(IcmpSessionTest, AnyRepliesReceived) {
  IcmpSession::IcmpSessionResult none_sent;
  EXPECT_FALSE(IcmpSession::AnyRepliesReceived(none_sent));

  IcmpSession::IcmpSessionResult two_sent_none_received = {
      base::TimeDelta(),
      base::TimeDelta(),
  };
  EXPECT_FALSE(IcmpSession::AnyRepliesReceived(two_sent_none_received));

  IcmpSession::IcmpSessionResult one_sent_one_received = {
      base::Seconds(10),
  };
  EXPECT_TRUE(IcmpSession::AnyRepliesReceived(one_sent_one_received));

  IcmpSession::IcmpSessionResult two_sent_one_received = {
      base::Seconds(20),
      base::TimeDelta(),
  };
  EXPECT_TRUE(IcmpSession::AnyRepliesReceived(two_sent_one_received));
}

TEST_F(IcmpSessionTest, IsPacketLossPercentageGreaterThan) {
  // If we sent no echo requests out, we expect no replies, therefore we have
  // 0% packet loss.
  IcmpSession::IcmpSessionResult none_sent_none_received;
  EXPECT_FALSE(IcmpSession::IsPacketLossPercentageGreaterThan(
      none_sent_none_received, 0));

  // If we receive all replies, we experience 0% packet loss.
  IcmpSession::IcmpSessionResult three_sent_three_received = {
      base::Seconds(10),
      base::Seconds(10),
      base::Seconds(10),
  };
  EXPECT_FALSE(IcmpSession::IsPacketLossPercentageGreaterThan(
      three_sent_three_received, 0));

  // If we sent 3 requests and received 2 replies, we have ~33% packet loss.
  IcmpSession::IcmpSessionResult three_sent_two_received = {
      base::Seconds(10),
      base::Seconds(10),
      base::TimeDelta(),
  };
  EXPECT_FALSE(IcmpSession::IsPacketLossPercentageGreaterThan(
      three_sent_two_received, 60));
  EXPECT_FALSE(IcmpSession::IsPacketLossPercentageGreaterThan(
      three_sent_two_received, 33));
  EXPECT_TRUE(IcmpSession::IsPacketLossPercentageGreaterThan(
      three_sent_two_received, 32));
  EXPECT_TRUE(IcmpSession::IsPacketLossPercentageGreaterThan(
      three_sent_two_received, 10));
}

}  // namespace shill
