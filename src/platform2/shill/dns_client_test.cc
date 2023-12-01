// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dns_client.h"

#include <netdb.h>
#include <sys/time.h>

#include <memory>
#include <string>
#include <vector>

#include <base/functional/bind.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>

#include "shill/error.h"
#include "shill/event_dispatcher.h"
#include "shill/mock_ares.h"
#include "shill/mock_control.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/net/io_handler.h"
#include "shill/net/mock_io_handler_factory.h"
#include "shill/net/mock_time.h"
#include "shill/testing.h"

using testing::_;
using testing::DoAll;
using testing::Not;
using testing::Return;
using testing::ReturnArg;
using testing::ReturnNew;
using testing::SetArgPointee;
using testing::StrEq;
using testing::StrictMock;
using testing::Test;

namespace shill {

namespace {
const char kGoodName[] = "all-systems.mcast.net";
const char kResult[] = "224.0.0.1";
const char kGoodServer[] = "8.8.8.8";
const char kBadServer[] = "10.9xx8.7";
const char kNetworkInterface[] = "eth0";
char kReturnAddressList0[] = {static_cast<char>(224), 0, 0, 1};
char* kReturnAddressList[] = {kReturnAddressList0, nullptr};
char kFakeAresChannelData = 0;
const ares_channel kAresChannel =
    reinterpret_cast<ares_channel>(&kFakeAresChannelData);
const int kAresFd = 10203;
const base::TimeDelta kAresTimeout =
    base::Seconds(2);  // ARES transaction timeout
const base::TimeDelta kAresWait =
    base::Seconds(1);  // Time period ARES asks caller to wait
}  // namespace

class DnsClientTest : public Test {
 public:
  DnsClientTest()
      : ares_result_(ARES_SUCCESS),
        address_result_(
            IPAddress::CreateFromFamily(IPAddress::kFamilyUnknown)) {
    time_val_.tv_sec = 0;
    time_val_.tv_usec = 0;
    ares_timeout_.tv_sec = kAresWait.InSeconds();
    ares_timeout_.tv_usec =
        kAresWait.InMicroseconds() % base::Time::kMicrosecondsPerSecond;
    hostent_.h_addrtype = IPAddress::kFamilyIPv4;
    hostent_.h_length = sizeof(kReturnAddressList0);
    hostent_.h_addr_list = kReturnAddressList;
  }

  void SetUp() override {
    EXPECT_CALL(time_, GetTimeMonotonic(_))
        .WillRepeatedly(DoAll(SetArgPointee<0>(time_val_), Return(0)));
    SetInActive();
  }

  void TearDown() override {
    // We need to make sure the dns_client instance releases ares_
    // before the destructor for DnsClientTest deletes ares_.
    if (dns_client_) {
      dns_client_->Stop();
    }
  }

  void AdvanceTime(base::TimeDelta time) {
    struct timeval adv_time = {
        static_cast<time_t>(time.InSeconds()),
        static_cast<suseconds_t>(time.InMicroseconds() %
                                 base::Time::kMicrosecondsPerSecond)};
    timeradd(&time_val_, &adv_time, &time_val_);
    EXPECT_CALL(time_, GetTimeMonotonic(_))
        .WillRepeatedly(DoAll(SetArgPointee<0>(time_val_), Return(0)));
  }

  void CallReplyCB() {
    dns_client_->ReceiveDnsReplyCB(dns_client_.get(), ares_result_, 0,
                                   &hostent_);
  }

  void CallDnsRead() { dns_client_->HandleDnsRead(kAresFd); }

  void CallDnsWrite() { dns_client_->HandleDnsWrite(kAresFd); }

  void CallTimeout() { dns_client_->HandleTimeout(); }

  void CallCompletion() { dns_client_->HandleCompletion(); }

  void CreateClient(base::TimeDelta timeout) {
    dns_client_.reset(new DnsClient(IPAddress::kFamilyIPv4, kNetworkInterface,
                                    timeout.InMilliseconds(), &dispatcher_,
                                    callback_target_.callback()));
    dns_client_->ares_ = &ares_;
    dns_client_->time_ = &time_;
    dns_client_->io_handler_factory_ = &io_handler_factory_;
  }

  void SetActive() {
    // Returns that socket kAresFd is readable.
    EXPECT_CALL(ares_, GetSock(_, _, _))
        .WillRepeatedly(DoAll(SetArgPointee<1>(kAresFd), Return(1)));
    EXPECT_CALL(ares_, Timeout(_, _, _))
        .WillRepeatedly(DoAll(SetArgPointee<2>(ares_timeout_), ReturnArg<2>()));
  }

  void SetInActive() {
    EXPECT_CALL(ares_, GetSock(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(ares_, Timeout(_, _, _)).WillRepeatedly(ReturnArg<1>());
  }

  void StartValidRequest() {
    CreateClient(kAresTimeout);

    EXPECT_CALL(io_handler_factory_,
                CreateIOReadyHandler(kAresFd, IOHandler::kModeInput, _))
        .WillRepeatedly(ReturnNew<IOHandler>());
    SetActive();
    EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, kAresWait));
    EXPECT_CALL(ares_, InitOptions(_, _, _))
        .WillOnce(DoAll(SetArgPointee<0>(kAresChannel), Return(ARES_SUCCESS)));
    EXPECT_CALL(ares_, SetLocalDev(kAresChannel, StrEq(kNetworkInterface)))
        .Times(1);
    EXPECT_CALL(ares_, SetServersCsv(_, StrEq(kGoodServer)))
        .WillOnce(Return(ARES_SUCCESS));
    EXPECT_CALL(ares_, GetHostByName(kAresChannel, StrEq(kGoodName), _, _, _));
    EXPECT_CALL(ares_, Destroy(kAresChannel));

    Error error;
    ASSERT_TRUE(dns_client_->Start({kGoodServer}, kGoodName, &error));
    EXPECT_TRUE(error.IsSuccess());
  }

  void TestValidCompletion() {
    EXPECT_CALL(ares_, ProcessFd(kAresChannel, kAresFd, ARES_SOCKET_BAD))
        .WillOnce(InvokeWithoutArgs(this, &DnsClientTest::CallReplyCB));
    ExpectPostCompletionTask();
    CallDnsRead();

    // Make sure that the address value is correct as held in the DnsClient.
    ASSERT_TRUE(dns_client_->address_.IsValid());
    const auto ipaddr = IPAddress::CreateFromString(kResult);
    CHECK(ipaddr.has_value());
    EXPECT_TRUE(ipaddr->Equals(dns_client_->address_));

    // Make sure the callback gets called with a success result, and save
    // the callback address argument in |address_result_|.
    EXPECT_CALL(callback_target_, CallTarget(IsSuccess(), _))
        .WillOnce(Invoke(this, &DnsClientTest::SaveCallbackArgs));
    CallCompletion();

    // Make sure the address was successfully passed to the callback.
    EXPECT_TRUE(ipaddr->Equals(address_result_));
    EXPECT_TRUE(dns_client_->address_.IsDefault());
  }

  void SaveCallbackArgs(const Error& error, const IPAddress& address) {
    error_result_ = error;
    address_result_ = address;
  }

  void ExpectPostCompletionTask() {
    EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
  }

  void ExpectReset() {
    EXPECT_TRUE(dns_client_->address_.family() == IPAddress::kFamilyIPv4);
    EXPECT_TRUE(dns_client_->address_.IsDefault());
    EXPECT_EQ(nullptr, dns_client_->resolver_state_);
  }

 protected:
  class DnsCallbackTarget {
   public:
    DnsCallbackTarget()
        : callback_(base::BindRepeating(&DnsCallbackTarget::CallTarget,
                                        base::Unretained(this))) {}

    MOCK_METHOD(void, CallTarget, (const Error&, const IPAddress&));

    const DnsClient::ClientCallback& callback() const { return callback_; }

   private:
    DnsClient::ClientCallback callback_;
  };

  MockIOHandlerFactory io_handler_factory_;
  std::unique_ptr<DnsClient> dns_client_;
  StrictMock<MockEventDispatcher> dispatcher_;
  std::string queued_request_;
  StrictMock<DnsCallbackTarget> callback_target_;
  StrictMock<MockAres> ares_;
  StrictMock<MockTime> time_;
  struct timeval time_val_;
  struct timeval ares_timeout_;
  struct hostent hostent_;
  int ares_result_;
  Error error_result_;
  IPAddress address_result_;
};

class SentinelIOHandler : public IOHandler {
 public:
  MOCK_METHOD(void, Die, ());
  virtual ~SentinelIOHandler() { Die(); }
};

TEST_F(DnsClientTest, Constructor) {
  CreateClient(kAresTimeout);
  ExpectReset();
}

// Correctly handles empty server addresses.
TEST_F(DnsClientTest, ServerJoin) {
  CreateClient(kAresTimeout);
  EXPECT_CALL(ares_, InitOptions(_, _, _))
      .WillOnce(DoAll(SetArgPointee<0>(kAresChannel), Return(ARES_SUCCESS)));
  EXPECT_CALL(ares_, SetServersCsv(_, StrEq(kGoodServer)))
      .WillOnce(Return(ARES_SUCCESS));
  EXPECT_CALL(ares_, SetLocalDev(kAresChannel, StrEq(kNetworkInterface)))
      .Times(1);
  EXPECT_CALL(ares_, GetHostByName(kAresChannel, StrEq(kGoodName), _, _, _));

  EXPECT_CALL(io_handler_factory_,
              CreateIOReadyHandler(kAresFd, IOHandler::kModeInput, _))
      .WillOnce(ReturnNew<IOHandler>());
  SetActive();
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, kAresWait));
  Error error;
  ASSERT_TRUE(dns_client_->Start({"", kGoodServer, "", ""}, kGoodName, &error));
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_CALL(ares_, Destroy(kAresChannel));
}

// Receive error because no DNS servers were specified.
TEST_F(DnsClientTest, NoServers) {
  CreateClient(kAresTimeout);
  Error error;
  EXPECT_FALSE(dns_client_->Start({}, kGoodName, &error));
  EXPECT_EQ(Error::kInvalidArguments, error.type());
}

// Setup error because SetServersCsv failed due to invalid DNS servers.
TEST_F(DnsClientTest, SetServersCsvInvalidServer) {
  CreateClient(kAresTimeout);
  EXPECT_CALL(ares_, InitOptions(_, _, _)).WillOnce(Return(ARES_SUCCESS));
  EXPECT_CALL(ares_, SetServersCsv(_, StrEq(kBadServer)))
      .WillOnce(Return(ARES_EBADSTR));
  Error error;
  EXPECT_FALSE(dns_client_->Start({kBadServer}, kGoodName, &error));
  EXPECT_EQ(Error::kOperationFailed, error.type());
}

// Setup error because InitOptions failed.
TEST_F(DnsClientTest, InitOptionsFailure) {
  CreateClient(kAresTimeout);
  EXPECT_CALL(ares_, InitOptions(_, _, _)).WillOnce(Return(ARES_EBADFLAGS));
  Error error;
  EXPECT_FALSE(dns_client_->Start({kGoodServer}, kGoodName, &error));
  EXPECT_EQ(Error::kOperationFailed, error.type());
}

// Fail a second request because one is already in progress.
TEST_F(DnsClientTest, MultipleRequest) {
  StartValidRequest();
  EXPECT_TRUE(dns_client_->IsActive());
  Error error;
  ASSERT_FALSE(dns_client_->Start({kGoodServer}, kGoodName, &error));
  EXPECT_EQ(Error::kInProgress, error.type());
}

TEST_F(DnsClientTest, GoodRequest) {
  StartValidRequest();
  TestValidCompletion();
}

TEST_F(DnsClientTest, GoodRequestWithTimeout) {
  StartValidRequest();
  // Insert an intermediate HandleTimeout callback.
  AdvanceTime(kAresWait);
  EXPECT_CALL(ares_, ProcessFd(kAresChannel, ARES_SOCKET_BAD, ARES_SOCKET_BAD));
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, kAresWait));
  CallTimeout();
  AdvanceTime(kAresWait);
  TestValidCompletion();
}

TEST_F(DnsClientTest, GoodRequestWithDnsRead) {
  StartValidRequest();
  // Insert an intermediate HandleDnsRead callback.
  AdvanceTime(kAresWait);
  EXPECT_CALL(ares_, ProcessFd(kAresChannel, kAresFd, ARES_SOCKET_BAD));
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, kAresWait));
  CallDnsRead();
  AdvanceTime(kAresWait);
  TestValidCompletion();
}

TEST_F(DnsClientTest, GoodRequestWithDnsWrite) {
  StartValidRequest();
  // Insert an intermediate HandleDnsWrite callback.
  AdvanceTime(kAresWait);
  EXPECT_CALL(ares_, ProcessFd(kAresChannel, ARES_SOCKET_BAD, kAresFd));
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, kAresWait));
  CallDnsWrite();
  AdvanceTime(kAresWait);
  TestValidCompletion();
}

// Failure due to the timeout occurring during first call to RefreshHandles.
TEST_F(DnsClientTest, TimeoutFirstRefresh) {
  CreateClient(kAresTimeout);
  EXPECT_CALL(ares_, InitOptions(_, _, _))
      .WillOnce(DoAll(SetArgPointee<0>(kAresChannel), Return(ARES_SUCCESS)));
  EXPECT_CALL(ares_, SetLocalDev(kAresChannel, StrEq(kNetworkInterface)))
      .Times(1);
  EXPECT_CALL(ares_, SetServersCsv(_, StrEq(kGoodServer)))
      .WillOnce(Return(ARES_SUCCESS));
  EXPECT_CALL(ares_, GetHostByName(kAresChannel, StrEq(kGoodName), _, _, _));
  struct timeval init_time_val = time_val_;
  AdvanceTime(kAresTimeout);
  EXPECT_CALL(time_, GetTimeMonotonic(_))
      .WillOnce(DoAll(SetArgPointee<0>(init_time_val), Return(0)))
      .WillRepeatedly(DoAll(SetArgPointee<0>(time_val_), Return(0)));
  EXPECT_CALL(callback_target_, CallTarget(Not(IsSuccess()), _)).Times(0);
  EXPECT_CALL(ares_, Destroy(kAresChannel));
  Error error;
  // Expect the DnsClient to post a completion task.  However this task will
  // never run since the Stop() gets called before returning.  We confirm
  // that the task indeed gets canceled below in ExpectReset().
  ExpectPostCompletionTask();
  ASSERT_FALSE(dns_client_->Start({kGoodServer}, kGoodName, &error));

  EXPECT_EQ(Error::kOperationTimeout, error.type());
  EXPECT_EQ(std::string(DnsClient::kErrorTimedOut), error.message());
  ExpectReset();
}

// Failed request due to timeout within the dns_client.
TEST_F(DnsClientTest, TimeoutDispatcherEvent) {
  StartValidRequest();
  EXPECT_CALL(ares_, ProcessFd(kAresChannel, ARES_SOCKET_BAD, ARES_SOCKET_BAD));
  AdvanceTime(kAresTimeout);
  ExpectPostCompletionTask();
  CallTimeout();
  EXPECT_CALL(callback_target_, CallTarget(ErrorIs(Error::kOperationTimeout,
                                                   DnsClient::kErrorTimedOut),
                                           _));
  CallCompletion();
}

// Failed request due to timeout reported by ARES.
TEST_F(DnsClientTest, TimeoutFromARES) {
  StartValidRequest();
  AdvanceTime(kAresWait);
  ares_result_ = ARES_ETIMEOUT;
  EXPECT_CALL(ares_, ProcessFd(kAresChannel, ARES_SOCKET_BAD, ARES_SOCKET_BAD))
      .WillOnce(InvokeWithoutArgs(this, &DnsClientTest::CallReplyCB));
  ExpectPostCompletionTask();
  CallTimeout();
  EXPECT_CALL(callback_target_, CallTarget(ErrorIs(Error::kOperationTimeout,
                                                   DnsClient::kErrorTimedOut),
                                           _));
  CallCompletion();
}

// Failed request due to "host not found" reported by ARES.
TEST_F(DnsClientTest, HostNotFound) {
  StartValidRequest();
  AdvanceTime(kAresWait);
  ares_result_ = ARES_ENOTFOUND;
  EXPECT_CALL(ares_, ProcessFd(kAresChannel, kAresFd, ARES_SOCKET_BAD))
      .WillOnce(InvokeWithoutArgs(this, &DnsClientTest::CallReplyCB));
  ExpectPostCompletionTask();
  CallDnsRead();
  EXPECT_CALL(callback_target_, CallTarget(ErrorIs(Error::kOperationFailed,
                                                   DnsClient::kErrorNotFound),
                                           _));
  CallCompletion();
}

// Make sure IOHandles are deallocated when GetSock() reports them gone.
TEST_F(DnsClientTest, IOHandleDeallocGetSock) {
  CreateClient(kAresTimeout);
  EXPECT_CALL(ares_, InitOptions(_, _, _))
      .WillOnce(DoAll(SetArgPointee<0>(kAresChannel), Return(ARES_SUCCESS)));
  EXPECT_CALL(ares_, SetLocalDev(kAresChannel, StrEq(kNetworkInterface)))
      .Times(1);
  EXPECT_CALL(ares_, SetServersCsv(_, StrEq(kGoodServer)))
      .WillOnce(Return(ARES_SUCCESS));
  EXPECT_CALL(ares_, GetHostByName(kAresChannel, StrEq(kGoodName), _, _, _));
  // This isn't any kind of scoped/ref pointer because we are tracking dealloc.
  SentinelIOHandler* io_handler = new SentinelIOHandler();
  EXPECT_CALL(io_handler_factory_,
              CreateIOReadyHandler(kAresFd, IOHandler::kModeInput, _))
      .WillOnce(Return(io_handler));
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, kAresWait));
  SetActive();
  Error error;
  ASSERT_TRUE(dns_client_->Start({kGoodServer}, kGoodName, &error));
  AdvanceTime(kAresWait);
  SetInActive();
  EXPECT_CALL(*io_handler, Die());
  EXPECT_CALL(ares_, ProcessFd(kAresChannel, kAresFd, ARES_SOCKET_BAD));
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, kAresWait));
  CallDnsRead();
  EXPECT_CALL(ares_, Destroy(kAresChannel));
}

// Make sure IOHandles are deallocated when Stop() is called.
TEST_F(DnsClientTest, IOHandleDeallocStop) {
  CreateClient(kAresTimeout);
  EXPECT_CALL(ares_, InitOptions(_, _, _))
      .WillOnce(DoAll(SetArgPointee<0>(kAresChannel), Return(ARES_SUCCESS)));
  EXPECT_CALL(ares_, SetLocalDev(kAresChannel, StrEq(kNetworkInterface)))
      .Times(1);
  EXPECT_CALL(ares_, SetServersCsv(_, StrEq(kGoodServer)))
      .WillOnce(Return(ARES_SUCCESS));
  EXPECT_CALL(ares_, GetHostByName(kAresChannel, StrEq(kGoodName), _, _, _));
  // This isn't any kind of scoped/ref pointer because we are tracking dealloc.
  SentinelIOHandler* io_handler = new SentinelIOHandler();
  EXPECT_CALL(io_handler_factory_,
              CreateIOReadyHandler(kAresFd, IOHandler::kModeInput, _))
      .WillOnce(Return(io_handler));
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, kAresWait));
  SetActive();
  Error error;
  ASSERT_TRUE(dns_client_->Start({kGoodServer}, kGoodName, &error));
  EXPECT_CALL(*io_handler, Die());
  EXPECT_CALL(ares_, Destroy(kAresChannel));
  dns_client_->Stop();
}

}  // namespace shill
