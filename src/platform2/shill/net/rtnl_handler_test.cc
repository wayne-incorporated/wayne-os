// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/rtnl_handler.h"

#include <limits>
#include <string>
#include <utility>

#include <gtest/gtest.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netlink.h>  // Needs typedefs from sys/socket.h.
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>

#include <base/functional/bind.h>
#include <base/test/test_future.h>
#include <base/test/task_environment.h>

#include "shill/mock_log.h"
#include "shill/net/mock_io_handler_factory.h"
#include "shill/net/mock_sockets.h"
#include "shill/net/rtnl_message.h"

using testing::_;
using testing::A;
using testing::AtLeast;
using testing::DoAll;
using testing::ElementsAre;
using testing::HasSubstr;
using testing::Return;
using testing::ReturnArg;
using testing::StrictMock;
using testing::Test;

namespace shill {

namespace {

const int kTestInterfaceIndex = 4;

ACTION(SetInterfaceIndex) {
  if (arg2) {
    reinterpret_cast<struct ifreq*>(arg2)->ifr_ifindex = kTestInterfaceIndex;
  }
}

MATCHER_P(MessageType, message_type, "") {
  return std::get<0>(arg).type() == message_type;
}

std::unique_ptr<RTNLMessage> CreateFakeMessage() {
  return std::make_unique<RTNLMessage>(RTNLMessage::kTypeLink,
                                       RTNLMessage::kModeGet, 0, 0, 0, 0,
                                       IPAddress::kFamilyUnknown);
}

}  // namespace

class RTNLHandlerTest : public Test {
 public:
  RTNLHandlerTest()
      : sockets_(new StrictMock<MockSockets>()),
        callback_(base::BindRepeating(&RTNLHandlerTest::HandlerCallback,
                                      base::Unretained(this))) {}

  void SetUp() override {
    RTNLHandler::GetInstance()->io_handler_factory_ = &io_handler_factory_;
    RTNLHandler::GetInstance()->sockets_.reset(sockets_);
  }

  void TearDown() override { RTNLHandler::GetInstance()->Stop(); }

  uint32_t GetRequestSequence() {
    return RTNLHandler::GetInstance()->request_sequence_;
  }

  void SetRequestSequence(uint32_t sequence) {
    RTNLHandler::GetInstance()->request_sequence_ = sequence;
  }

  bool SendMessageWithErrorMask(std::unique_ptr<RTNLMessage> message,
                                const RTNLHandler::ErrorMask& error_mask,
                                uint32_t* msg_seq) {
    return RTNLHandler::GetInstance()->SendMessageWithErrorMask(
        std::move(message), error_mask, msg_seq);
  }

  bool IsSequenceInErrorMaskWindow(uint32_t sequence) {
    return RTNLHandler::GetInstance()->IsSequenceInErrorMaskWindow(sequence);
  }

  void SetErrorMask(uint32_t sequence,
                    const RTNLHandler::ErrorMask& error_mask) {
    return RTNLHandler::GetInstance()->SetErrorMask(sequence, error_mask);
  }

  RTNLHandler::ErrorMask GetAndClearErrorMask(uint32_t sequence) {
    return RTNLHandler::GetInstance()->GetAndClearErrorMask(sequence);
  }

  int GetErrorWindowSize() { return RTNLHandler::kErrorWindowSize; }

  void StoreRequest(std::unique_ptr<RTNLMessage> request) {
    RTNLHandler::GetInstance()->StoreRequest(std::move(request));
  }

  std::unique_ptr<RTNLMessage> PopStoredRequest(uint32_t seq) {
    return RTNLHandler::GetInstance()->PopStoredRequest(seq);
  }

  uint32_t CalculateStoredRequestWindowSize() {
    return RTNLHandler::GetInstance()->CalculateStoredRequestWindowSize();
  }

  uint32_t stored_request_window_size() {
    return RTNLHandler::GetInstance()->kStoredRequestWindowSize;
  }

  uint32_t oldest_request_sequence() {
    return RTNLHandler::GetInstance()->oldest_request_sequence_;
  }

  MOCK_METHOD(void, HandlerCallback, (const RTNLMessage&));

 protected:
  static const int kTestSocket;
  static const int kTestDeviceIndex;
  static const char kTestDeviceName[];

  void AddLink();
  void AddNeighbor();
  void StartRTNLHandler();
  void StopRTNLHandler();
  void ReturnError(uint32_t sequence, int error_number);

  MockSockets* sockets_;
  StrictMock<MockIOHandlerFactory> io_handler_factory_;
  base::RepeatingCallback<void(const RTNLMessage&)> callback_;

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
};

const int RTNLHandlerTest::kTestSocket = 123;
const int RTNLHandlerTest::kTestDeviceIndex = 123456;
const char RTNLHandlerTest::kTestDeviceName[] = "test-device";

void RTNLHandlerTest::StartRTNLHandler() {
  EXPECT_CALL(*sockets_,
              Socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE))
      .WillOnce(Return(kTestSocket));
  EXPECT_CALL(*sockets_, Bind(kTestSocket, _, sizeof(sockaddr_nl)))
      .WillOnce(Return(0));
  EXPECT_CALL(*sockets_, SetReceiveBuffer(kTestSocket, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Return(0));
  EXPECT_CALL(io_handler_factory_, CreateIOInputHandler(kTestSocket, _, _));
  RTNLHandler::GetInstance()->Start(0);
}

void RTNLHandlerTest::StopRTNLHandler() {
  EXPECT_CALL(*sockets_, Close(kTestSocket)).WillOnce(Return(0));
  RTNLHandler::GetInstance()->Stop();
}

void RTNLHandlerTest::AddLink() {
  RTNLMessage message(RTNLMessage::kTypeLink, RTNLMessage::kModeAdd, 0, 0, 0,
                      kTestDeviceIndex, IPAddress::kFamilyIPv4);
  message.SetAttribute(static_cast<uint16_t>(IFLA_IFNAME),
                       ByteString(std::string(kTestDeviceName), true));
  ByteString b(message.Encode());
  InputData data(b.GetData(), b.GetLength());
  RTNLHandler::GetInstance()->ParseRTNL(&data);
}

void RTNLHandlerTest::AddNeighbor() {
  RTNLMessage message(RTNLMessage::kTypeNeighbor, RTNLMessage::kModeAdd, 0, 0,
                      0, kTestDeviceIndex, IPAddress::kFamilyIPv4);
  ByteString encoded(message.Encode());
  InputData data(encoded.GetData(), encoded.GetLength());
  RTNLHandler::GetInstance()->ParseRTNL(&data);
}

void RTNLHandlerTest::ReturnError(uint32_t sequence, int error_number) {
  struct {
    struct nlmsghdr hdr;
    struct nlmsgerr err;
  } errmsg;

  memset(&errmsg, 0, sizeof(errmsg));
  errmsg.hdr.nlmsg_type = NLMSG_ERROR;
  errmsg.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(errmsg.err));
  errmsg.hdr.nlmsg_seq = sequence;
  errmsg.err.error = -error_number;

  InputData data(reinterpret_cast<unsigned char*>(&errmsg), sizeof(errmsg));
  RTNLHandler::GetInstance()->ParseRTNL(&data);
}

TEST_F(RTNLHandlerTest, ListenersInvoked) {
  StartRTNLHandler();

  std::unique_ptr<RTNLListener> link_listener(
      new RTNLListener(RTNLHandler::kRequestLink, callback_));
  std::unique_ptr<RTNLListener> neighbor_listener(
      new RTNLListener(RTNLHandler::kRequestNeighbor, callback_));

  EXPECT_CALL(*this, HandlerCallback(A<const RTNLMessage&>()))
      .With(MessageType(RTNLMessage::kTypeLink));
  EXPECT_CALL(*this, HandlerCallback(A<const RTNLMessage&>()))
      .With(MessageType(RTNLMessage::kTypeNeighbor));

  AddLink();
  AddNeighbor();

  StopRTNLHandler();
}

TEST_F(RTNLHandlerTest, GetInterfaceName) {
  EXPECT_EQ(-1, RTNLHandler::GetInstance()->GetInterfaceIndex(""));
  {
    struct ifreq ifr;
    std::string name(sizeof(ifr.ifr_name), 'x');
    EXPECT_EQ(-1, RTNLHandler::GetInstance()->GetInterfaceIndex(name));
  }

  const int kTestSocket = 123;
  EXPECT_CALL(*sockets_, Socket(PF_INET, _, 0))
      .Times(3)
      .WillOnce(Return(-1))
      .WillRepeatedly(Return(kTestSocket));
  EXPECT_CALL(*sockets_, Ioctl(kTestSocket, SIOCGIFINDEX, _))
      .WillOnce(Return(-1))
      .WillOnce(DoAll(SetInterfaceIndex(), Return(0)));
  EXPECT_CALL(*sockets_, Close(kTestSocket)).Times(2).WillRepeatedly(Return(0));
  EXPECT_EQ(-1, RTNLHandler::GetInstance()->GetInterfaceIndex("eth0"));
  EXPECT_EQ(-1, RTNLHandler::GetInstance()->GetInterfaceIndex("wlan0"));
  EXPECT_EQ(kTestInterfaceIndex,
            RTNLHandler::GetInstance()->GetInterfaceIndex("usb0"));
}

TEST_F(RTNLHandlerTest, IsSequenceInErrorMaskWindow) {
  const uint32_t kRequestSequence = 1234;
  SetRequestSequence(kRequestSequence);
  EXPECT_FALSE(IsSequenceInErrorMaskWindow(kRequestSequence + 1));
  EXPECT_TRUE(IsSequenceInErrorMaskWindow(kRequestSequence));
  EXPECT_TRUE(IsSequenceInErrorMaskWindow(kRequestSequence - 1));
  EXPECT_TRUE(
      IsSequenceInErrorMaskWindow(kRequestSequence - GetErrorWindowSize() + 1));
  EXPECT_FALSE(
      IsSequenceInErrorMaskWindow(kRequestSequence - GetErrorWindowSize()));
  EXPECT_FALSE(
      IsSequenceInErrorMaskWindow(kRequestSequence - GetErrorWindowSize() - 1));
}

TEST_F(RTNLHandlerTest, SendMessageReturnsErrorAndAdvancesSequenceNumber) {
  StartRTNLHandler();
  const uint32_t kSequenceNumber = 123;
  SetRequestSequence(kSequenceNumber);
  EXPECT_CALL(*sockets_, Send(kTestSocket, _, _, 0)).WillOnce(Return(-1));
  uint32_t seq = 0;
  EXPECT_FALSE(
      RTNLHandler::GetInstance()->SendMessage(CreateFakeMessage(), &seq));

  // |seq| should not be set if there was a failure.
  EXPECT_EQ(seq, 0);
  // Sequence number should still increment even if there was a failure.
  EXPECT_EQ(kSequenceNumber + 1, GetRequestSequence());
  StopRTNLHandler();
}

TEST_F(RTNLHandlerTest, SendMessageWithEmptyMask) {
  StartRTNLHandler();
  const uint32_t kSequenceNumber = 123;
  SetRequestSequence(kSequenceNumber);
  SetErrorMask(kSequenceNumber, {1, 2, 3});
  EXPECT_CALL(*sockets_, Send(kTestSocket, _, _, 0)).WillOnce(ReturnArg<2>());
  uint32_t seq;
  EXPECT_TRUE(SendMessageWithErrorMask(CreateFakeMessage(), {}, &seq));
  EXPECT_EQ(seq, kSequenceNumber);
  EXPECT_EQ(kSequenceNumber + 1, GetRequestSequence());
  EXPECT_TRUE(GetAndClearErrorMask(kSequenceNumber).empty());
  StopRTNLHandler();
}

TEST_F(RTNLHandlerTest, SendMessageWithErrorMask) {
  StartRTNLHandler();
  const uint32_t kSequenceNumber = 123;
  SetRequestSequence(kSequenceNumber);
  EXPECT_CALL(*sockets_, Send(kTestSocket, _, _, 0)).WillOnce(ReturnArg<2>());
  uint32_t seq;
  EXPECT_TRUE(SendMessageWithErrorMask(CreateFakeMessage(), {1, 2, 3}, &seq));
  EXPECT_EQ(seq, kSequenceNumber);
  EXPECT_EQ(kSequenceNumber + 1, GetRequestSequence());
  EXPECT_TRUE(GetAndClearErrorMask(kSequenceNumber + 1).empty());
  EXPECT_THAT(GetAndClearErrorMask(kSequenceNumber), ElementsAre(1, 2, 3));

  // A second call to GetAndClearErrorMask() returns an empty vector.
  EXPECT_TRUE(GetAndClearErrorMask(kSequenceNumber).empty());
  StopRTNLHandler();
}

TEST_F(RTNLHandlerTest, SendMessageInferredErrorMasks) {
  struct {
    RTNLMessage::Type type;
    RTNLMessage::Mode mode;
    RTNLHandler::ErrorMask mask;
  } expectations[] = {
      {RTNLMessage::kTypeLink, RTNLMessage::kModeGet, {}},
      {RTNLMessage::kTypeLink, RTNLMessage::kModeAdd, {EEXIST}},
      {RTNLMessage::kTypeLink, RTNLMessage::kModeDelete, {ESRCH, ENODEV}},
      {RTNLMessage::kTypeAddress,
       RTNLMessage::kModeDelete,
       {ESRCH, ENODEV, EADDRNOTAVAIL}}};
  const uint32_t kSequenceNumber = 123;
  EXPECT_CALL(*sockets_, Send(_, _, _, 0)).WillRepeatedly(ReturnArg<2>());
  for (const auto& expectation : expectations) {
    SetRequestSequence(kSequenceNumber);
    auto message =
        std::make_unique<RTNLMessage>(expectation.type, expectation.mode, 0, 0,
                                      0, 0, IPAddress::kFamilyUnknown);
    EXPECT_TRUE(
        RTNLHandler::GetInstance()->SendMessage(std::move(message), nullptr));
    EXPECT_EQ(expectation.mask, GetAndClearErrorMask(kSequenceNumber));
  }
}

TEST_F(RTNLHandlerTest, MaskedError) {
  StartRTNLHandler();
  const uint32_t kSequenceNumber = 123;
  SetRequestSequence(kSequenceNumber);
  EXPECT_CALL(*sockets_, Send(kTestSocket, _, _, 0)).WillOnce(ReturnArg<2>());
  uint32_t seq;
  EXPECT_TRUE(SendMessageWithErrorMask(CreateFakeMessage(), {1, 2, 3}, &seq));
  EXPECT_EQ(seq, kSequenceNumber);
  ScopedMockLog log;

  // This error will be not be masked since this sequence number has no mask.
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _, HasSubstr("error 1")))
      .Times(1);
  ReturnError(kSequenceNumber - 1, 1);

  // This error will be masked.
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _, HasSubstr("error 2")))
      .Times(0);
  ReturnError(kSequenceNumber, 2);

  // This second error will be not be masked since the error mask was removed.
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _, HasSubstr("error 3")))
      .Times(1);
  ReturnError(kSequenceNumber, 3);

  StopRTNLHandler();
}

TEST_F(RTNLHandlerTest, BasicStoreRequest) {
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 0);

  const uint32_t kSequenceNumber1 = 123;
  auto request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber1);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 1);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber1);

  const uint32_t kSequenceNumber2 = 124;
  request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber2);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 2);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber1);

  const uint32_t kSequenceNumber3 =
      kSequenceNumber1 + stored_request_window_size() - 1;
  request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber3);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), stored_request_window_size());
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber1);

  EXPECT_NE(PopStoredRequest(kSequenceNumber1), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber1), nullptr);
  EXPECT_EQ(CalculateStoredRequestWindowSize(),
            stored_request_window_size() - 1);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber2);

  EXPECT_NE(PopStoredRequest(kSequenceNumber2), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber2), nullptr);
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 1);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber3);

  EXPECT_NE(PopStoredRequest(kSequenceNumber3), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber3), nullptr);
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 0);
}

TEST_F(RTNLHandlerTest, StoreRequestLargerThanWindow) {
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 0);

  const uint32_t kSequenceNumber1 = 123;
  auto request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber1);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 1);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber1);

  const uint32_t kSequenceNumber2 = 124;
  request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber2);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 2);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber1);

  const uint32_t kSequenceNumber3 =
      kSequenceNumber1 + stored_request_window_size();
  request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber3);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), stored_request_window_size());
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber2);

  const uint32_t kSequenceNumber4 =
      kSequenceNumber2 + stored_request_window_size();
  request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber4);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 2);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber3);

  EXPECT_EQ(PopStoredRequest(kSequenceNumber1), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber2), nullptr);

  EXPECT_NE(PopStoredRequest(kSequenceNumber3), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber3), nullptr);
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 1);

  EXPECT_NE(PopStoredRequest(kSequenceNumber4), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber4), nullptr);
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 0);
}

TEST_F(RTNLHandlerTest, OverflowStoreRequest) {
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 0);

  const uint32_t kSequenceNumber1 = std::numeric_limits<uint32_t>::max();
  auto request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber1);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 1);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber1);

  const uint32_t kSequenceNumber2 = kSequenceNumber1 + 1;
  request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber2);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 2);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber1);

  const uint32_t kSequenceNumber3 =
      kSequenceNumber1 + stored_request_window_size() - 1;
  request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber3);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), stored_request_window_size());
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber1);

  EXPECT_NE(PopStoredRequest(kSequenceNumber1), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber1), nullptr);
  EXPECT_EQ(CalculateStoredRequestWindowSize(),
            stored_request_window_size() - 1);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber2);

  EXPECT_NE(PopStoredRequest(kSequenceNumber2), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber2), nullptr);
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 1);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber3);

  EXPECT_NE(PopStoredRequest(kSequenceNumber3), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber3), nullptr);
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 0);
}

TEST_F(RTNLHandlerTest, OverflowStoreRequestLargerThanWindow) {
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 0);

  const uint32_t kSequenceNumber1 = std::numeric_limits<uint32_t>::max();
  auto request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber1);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 1);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber1);

  const uint32_t kSequenceNumber2 = kSequenceNumber1 + 1;
  request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber2);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 2);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber1);

  const uint32_t kSequenceNumber3 =
      kSequenceNumber1 + stored_request_window_size();
  request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber3);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), stored_request_window_size());
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber2);

  const uint32_t kSequenceNumber4 =
      kSequenceNumber2 + stored_request_window_size();
  request = std::make_unique<RTNLMessage>();
  request->set_seq(kSequenceNumber4);
  StoreRequest(std::move(request));
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 2);
  EXPECT_EQ(oldest_request_sequence(), kSequenceNumber3);

  EXPECT_EQ(PopStoredRequest(kSequenceNumber1), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber2), nullptr);

  EXPECT_NE(PopStoredRequest(kSequenceNumber3), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber3), nullptr);
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 1);

  EXPECT_NE(PopStoredRequest(kSequenceNumber4), nullptr);
  EXPECT_EQ(PopStoredRequest(kSequenceNumber4), nullptr);
  EXPECT_EQ(CalculateStoredRequestWindowSize(), 0);
}

TEST_F(RTNLHandlerTest, SetInterfaceMac) {
  StartRTNLHandler();
  constexpr uint32_t kSequenceNumber = 123456;
  constexpr int32_t kErrorNumber = 115;
  SetRequestSequence(kSequenceNumber);
  EXPECT_CALL(*sockets_, Send(kTestSocket, _, _, 0)).WillOnce(ReturnArg<2>());

  base::test::TestFuture<int32_t> error_future;

  RTNLHandler::GetInstance()->SetInterfaceMac(
      3, ByteString::CreateFromHexString("abcdef123456"),
      error_future.GetCallback());

  ReturnError(kSequenceNumber, kErrorNumber);

  EXPECT_EQ(error_future.Get(), kErrorNumber);

  StopRTNLHandler();
}

TEST_F(RTNLHandlerTest, AddInterfaceTest) {
  StartRTNLHandler();
  constexpr uint32_t kSequenceNumber = 123456;
  constexpr int32_t kErrorNumber = 115;
  const std::string kIfName = "wg0";
  const std::string kIfType = "wireguard";
  SetRequestSequence(kSequenceNumber);

  ByteString msg_bytes;
  EXPECT_CALL(*sockets_, Send(kTestSocket, _, _, 0))
      .WillOnce([&](int, const void* buf, size_t len, int flags) {
        msg_bytes = ByteString{reinterpret_cast<const char*>(buf), len};
        return len;
      });

  base::test::TestFuture<int32_t> error_future;

  RTNLHandler::GetInstance()->AddInterface(kIfName, kIfType, ByteString{},
                                           error_future.GetCallback());

  RTNLMessage sent_msg;
  sent_msg.Decode(msg_bytes.GetConstData(), msg_bytes.GetLength());
  EXPECT_EQ(sent_msg.flags(),
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
  EXPECT_EQ(sent_msg.GetIflaIfname(), kIfName);
  ASSERT_TRUE(sent_msg.link_status().kind.has_value());
  EXPECT_EQ(sent_msg.link_status().kind.value(), kIfType);

  ReturnError(kSequenceNumber, kErrorNumber);

  EXPECT_EQ(error_future.Get(), kErrorNumber);

  StopRTNLHandler();
}

}  // namespace shill
