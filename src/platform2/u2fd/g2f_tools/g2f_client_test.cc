// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <base/check.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_number_conversions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hidapi/hidapi.h>
#include <memory>
#include <vector>

#include "u2fd/g2f_tools/g2f_client.h"

namespace {

hid_device* kDummyDevice = reinterpret_cast<hid_device*>(0xdeadbeef);

constexpr char kDummyDeviceName[] = "DummyDeviceName";

constexpr char kDummySingleResponse[] =
    "AABBCCDD860008DEADBEEF000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000";

constexpr char kDummyLargeResponse[] =
    "AABBCCDD860050DEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDE"
    "DEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDE";

constexpr char kDummyLargeResponseCont[] =
    "AABBCCDD00DEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDE"
    "DEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDE";

constexpr size_t kRwBufSize = u2f::kU2fReportSize * 4;

int hid_open_called;
int hid_close_called;

unsigned char hid_write_data[kRwBufSize];
int hid_write_count;

unsigned char hid_read_data[kRwBufSize];
int hid_read_count;

bool hid_read_fail_timeout = false;

}  // namespace

hid_device* hid_open_path(const char* path) {
  EXPECT_THAT(path, ::testing::StrEq(kDummyDeviceName));
  hid_open_called++;
  return kDummyDevice;
}

void hid_close(hid_device* device) {
  EXPECT_EQ(device, kDummyDevice);
  hid_close_called++;
}

int hid_write(hid_device* device, const unsigned char* data, size_t length) {
  EXPECT_EQ(device, kDummyDevice);
  length = std::min(length, kRwBufSize - hid_write_count);
  memcpy(hid_write_data + hid_write_count, data, length);
  hid_write_count += length;
  return length;
}

int hid_read_timeout(hid_device* device,
                     unsigned char* data,
                     size_t length,
                     int milliseconds) {
  length = std::min(length, kRwBufSize - hid_read_count);
  if (hid_read_fail_timeout) {
    // sleep
  }
  EXPECT_EQ(device, kDummyDevice);
  memcpy(data, hid_read_data + hid_read_count, length);
  hid_read_count += length;
  return length;
}

const wchar_t* hid_error(hid_device* device) {
  return nullptr;
}

namespace g2f_client {
namespace {

using ::testing::_;
using ::testing::ByRef;
using ::testing::ContainerEq;
using ::testing::DoAll;
using ::testing::Each;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::InvokeWithoutArgs;
using ::testing::MatcherCast;
using ::testing::MatchesRegex;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::StrEq;

static HidDevice::Cid kDummyCid = {{0xAA, 0xBB, 0xCC, 0xDD}};
static constexpr int kHidTimeoutMs = 100;

class G2fClientTest : public ::testing::Test {
 public:
  G2fClientTest() = default;
  G2fClientTest(const G2fClientTest&) = delete;
  G2fClientTest& operator=(const G2fClientTest&) = delete;

  ~G2fClientTest() override = default;

  void SetUp() override {
    hid_open_called = 0;
    hid_close_called = 0;
    memset(hid_write_data, 0, kRwBufSize);
    hid_write_count = 0;
    memset(hid_read_data, 0, kRwBufSize);
    hid_read_count = 0;
    hid_read_fail_timeout = false;
    device_.reset(new HidDevice(kDummyDeviceName));
  }

 protected:
  std::unique_ptr<HidDevice> device_;
};

TEST_F(G2fClientTest, HidDeviceOpenClose) {
  // Sanity check.
  EXPECT_EQ(0, hid_open_called);
  EXPECT_EQ(0, hid_close_called);

  EXPECT_FALSE(device_->IsOpened());
  EXPECT_TRUE(device_->Open());
  EXPECT_TRUE(device_->IsOpened());

  EXPECT_EQ(1, hid_open_called);
  EXPECT_EQ(0, hid_close_called);

  // Does not open multiple times.
  EXPECT_TRUE(device_->Open());
  EXPECT_TRUE(device_->IsOpened());

  EXPECT_EQ(1, hid_open_called);
  EXPECT_EQ(0, hid_close_called);

  device_->Close();
  EXPECT_FALSE(device_->IsOpened());

  EXPECT_EQ(1, hid_open_called);
  EXPECT_EQ(1, hid_close_called);
}

TEST_F(G2fClientTest, HidDeviceSendWithoutOpen) {
  brillo::Blob payload;
  EXPECT_FALSE(device_->SendRequest(kDummyCid, 0, payload));
}

TEST_F(G2fClientTest, HidDeviceRecvWithoutOpen) {
  uint8_t cmd;
  brillo::Blob payload;
  EXPECT_FALSE(device_->RecvResponse(kDummyCid, &cmd, &payload, 0));
}

TEST_F(G2fClientTest, HidDeviceSend) {
  EXPECT_TRUE(device_->Open());

  brillo::Blob payload{0xDD, 0xFF};
  EXPECT_TRUE(device_->SendRequest(kDummyCid, 0xAB, payload));

  EXPECT_THAT(base::HexEncode(hid_write_data, hid_write_count),
              MatchesRegex(".*"
                           "AABBCCDD.*"  // Cid
                           "AB.*"        // Command
                           "DDFF.*"));   // Payload
}

TEST_F(G2fClientTest, HidDeviceSendMultipleFrames) {
  EXPECT_TRUE(device_->Open());

  brillo::Blob payload;
  for (int i = 0; i < u2f::kU2fReportSize * 2; i++) {
    payload.push_back(i);
  }
  EXPECT_TRUE(device_->SendRequest(kDummyCid, 0xAB, payload));

  EXPECT_THAT(base::HexEncode(hid_write_data, hid_write_count),
              MatchesRegex(".*"
                           "AABBCCDD.*"  // Cid
                           "AB.*"        // Command
                           "010203.*"    // Payload
                           // Second frame:
                           "AABBCCDD.*"   // Cid
                           "01.*"         // Cont
                           "747576.*"));  // Payload
}

TEST_F(G2fClientTest, HidDeviceSendTooLarge) {
  EXPECT_TRUE(device_->Open());

  brillo::Blob payload(UINT16_MAX + 1, 0);
  EXPECT_FALSE(device_->SendRequest(kDummyCid, 0xAB, payload));
}

TEST_F(G2fClientTest, HidDeviceSendWriteFails) {
  EXPECT_TRUE(device_->Open());

  // Pretend the whole buffer has been read already;
  // subsequent reads will fail.
  hid_write_count = sizeof(hid_write_data);

  brillo::Blob payload(10, 0);
  EXPECT_FALSE(device_->SendRequest(kDummyCid, 0xAB, payload));
}

namespace {

void HexStringToBuffer(const char* str, unsigned char** dest) {
  std::vector<uint8_t> bytes;
  CHECK(base::HexStringToBytes(str, &bytes));
  std::copy(bytes.begin(), bytes.end(), *dest);
  *dest += bytes.size();
}

}  // namespace

TEST_F(G2fClientTest, HidDeviceRecvResponse) {
  unsigned char* dest = hid_read_data;
  HexStringToBuffer(kDummySingleResponse, &dest);

  uint8_t cmd;
  brillo::Blob payload;

  EXPECT_TRUE(device_->Open());
  EXPECT_TRUE(device_->RecvResponse(kDummyCid, &cmd, &payload, kHidTimeoutMs));

  EXPECT_THAT(payload, ElementsAre(0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0));
}

TEST_F(G2fClientTest, HidDeviceRecvResponseMultiPart) {
  unsigned char* dest = hid_read_data;
  HexStringToBuffer(kDummyLargeResponse, &dest);
  HexStringToBuffer(kDummyLargeResponseCont, &dest);

  uint8_t cmd;
  brillo::Blob payload;

  EXPECT_TRUE(device_->Open());
  EXPECT_TRUE(device_->RecvResponse(kDummyCid, &cmd, &payload, kHidTimeoutMs));

  EXPECT_EQ(0x50, payload.size());
  EXPECT_THAT(payload, Each(0xDE));
}

TEST_F(G2fClientTest, HidDeviceRecvResponseUnexpectedInit) {
  unsigned char* dest = hid_read_data;
  HexStringToBuffer(kDummyLargeResponse, &dest);
  HexStringToBuffer(kDummyLargeResponse, &dest);

  uint8_t cmd;
  brillo::Blob payload;

  EXPECT_TRUE(device_->Open());
  EXPECT_FALSE(device_->RecvResponse(kDummyCid, &cmd, &payload, kHidTimeoutMs));
}

TEST_F(G2fClientTest, HidDeviceRecvResponseUnexpectedCont) {
  unsigned char* dest = hid_read_data;
  HexStringToBuffer(kDummyLargeResponseCont, &dest);

  uint8_t cmd;
  brillo::Blob payload;

  EXPECT_TRUE(device_->Open());
  EXPECT_FALSE(device_->RecvResponse(kDummyCid, &cmd, &payload, kHidTimeoutMs));
}

TEST_F(G2fClientTest, HidDeviceRecvResponseUnexpectedChannel) {
  unsigned char* dest = hid_read_data;
  HexStringToBuffer(kDummySingleResponse, &dest);

  uint8_t cmd;
  brillo::Blob payload;

  EXPECT_TRUE(device_->Open());
  EXPECT_FALSE(device_->RecvResponse({0xFF, 0xFF, 0xFF, 0xFF}, &cmd, &payload,
                                     kHidTimeoutMs));
}

TEST_F(G2fClientTest, HidDeviceRecvResponseUnexpectedSeq) {
  unsigned char* dest = hid_read_data;
  HexStringToBuffer(kDummyLargeResponse, &dest);
  HexStringToBuffer(kDummyLargeResponseCont, &dest);

  hid_read_data[4] = 7;

  uint8_t cmd;
  brillo::Blob payload;

  EXPECT_TRUE(device_->Open());
  EXPECT_FALSE(device_->RecvResponse(kDummyCid, &cmd, &payload, kHidTimeoutMs));
}

TEST_F(G2fClientTest, HidDeviceRecvResponseReadFail) {
  // Simulate having read all data; subsequent reads will fail.
  hid_read_count = sizeof(hid_read_data);

  uint8_t cmd;
  brillo::Blob payload;

  EXPECT_TRUE(device_->Open());
  EXPECT_FALSE(device_->RecvResponse(kDummyCid, &cmd, &payload, kHidTimeoutMs));
}

class MockHidDevice : public HidDevice {
 public:
  MockHidDevice() : HidDevice("unused") {}
  MOCK_METHOD(bool, IsOpened, (), (const, override));
  MOCK_METHOD(bool, Open, (), (override));
  MOCK_METHOD(void, Close, (), (override));
  MOCK_METHOD(bool,
              SendRequest,
              (const Cid&, uint8_t, const brillo::Blob&),
              (override));
  MOCK_METHOD(bool,
              RecvResponse,
              (const Cid&, uint8_t*, brillo::Blob*, int),
              (override));
};

class U2FHidTest : public ::testing::Test {
 public:
  U2FHidTest() : hid_(&device_) {}
  U2FHidTest(const U2FHidTest&) = delete;
  U2FHidTest& operator=(const U2FHidTest&) = delete;

  ~U2FHidTest() override = default;

 protected:
  void ExpectInit(bool copy_nonce,
                  const char* cid,
                  const char* version,
                  const char* caps);

  void ExpectDefaultInit() { ExpectInit(true, "AABBCCDD", "00000000", "00"); }

  void ExpectMsg(U2FHid::CommandCode cmd, bool echo_req);

  MockHidDevice device_;
  U2FHid hid_;

  U2FHid::Command request;
  U2FHid::Command response;
  brillo::Blob nonce;
};

MATCHER(IsBroadcastCid, "Matches the broadcast cid.") {
  return arg.raw[0] == 0xFF && arg.raw[1] == 0xFF && arg.raw[2] == 0xFF &&
         arg.raw[3] == 0xFF;
}

MATCHER_P(EqCommandCode, value, "Matches the specified command code") {
  return arg == static_cast<uint8_t>(value);
}

ACTION_P4(PrepareInitResponse, copy_nonce, req, resp, str) {
  if (copy_nonce)
    *resp = *req;
  std::vector<uint8_t> bytes;
  LOG(ERROR) << str;
  CHECK(base::HexStringToBytes(str, &bytes));
  std::copy(bytes.begin(), bytes.end(), std::back_inserter(*resp));
}

void U2FHidTest::ExpectInit(bool copy_nonce,
                            const char* cid,
                            const char* version,
                            const char* caps) {
  EXPECT_CALL(device_, Open()).WillOnce(Return(true));

  std::string resp = base::StringPrintf("%s%s%s", cid, version, caps);

  EXPECT_CALL(device_,
              SendRequest(IsBroadcastCid(),
                          EqCommandCode(U2FHid::CommandCode::kInit), _))
      .WillOnce(DoAll(SaveArg<2>(&request.payload),
                      PrepareInitResponse(copy_nonce, &request.payload,
                                          &response.payload, resp),
                      Return(true)));

  EXPECT_CALL(device_, RecvResponse(_, _, _, _))
      .WillOnce(DoAll(
          SetArgPointee<1>(static_cast<uint8_t>(U2FHid::CommandCode::kInit)),
          SetArgPointee<2>(ByRef(response.payload)), Return(true)));
}

void U2FHidTest::ExpectMsg(U2FHid::CommandCode cmd, bool echo_req) {
  EXPECT_CALL(device_, Open()).WillOnce(Return(true));

  EXPECT_CALL(device_, SendRequest(_, EqCommandCode(cmd), _))
      .WillOnce(DoAll(SaveArg<2>(&request.payload),
                      InvokeWithoutArgs([this, echo_req]() {
                        if (echo_req)
                          response.payload = request.payload;
                        else
                          response.payload.clear();
                      }),
                      Return(true)));

  EXPECT_CALL(device_, RecvResponse(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(static_cast<uint8_t>(cmd)),
                      SetArgPointee<2>(ByRef(response.payload)), Return(true)));
}

TEST_F(U2FHidTest, Init) {
  ExpectInit(true,        // Copy nonce
             "AABBCCDD",  // Cid
             "00000000",  // Version
             "DE");       // Caps
  EXPECT_TRUE(hid_.Init(false));
  EXPECT_TRUE(hid_.Initialized());
  EXPECT_EQ(00, hid_.GetVersion().protocol);
  EXPECT_EQ(0xDE, hid_.GetCaps());

  // Calling again does not re-initialize.
  EXPECT_TRUE(hid_.Init(false));
  EXPECT_TRUE(hid_.Initialized());

  ExpectInit(true,        // Copy nonce
             "AABBCCDD",  // Cid
             "DEADBEEF",  // Version
             "AF");       // Caps

  // Force re-initialization
  EXPECT_TRUE(hid_.Init(true));
  EXPECT_TRUE(hid_.Initialized());
  EXPECT_EQ(0xEF, hid_.GetVersion().build);
  EXPECT_EQ(0xAF, hid_.GetCaps());
}

TEST_F(U2FHidTest, InitBadResponseSize) {
  ExpectInit(true,        // Copy nonce
             "AABBCCDD",  // Cid
             "00",        // Version - too short!
             "DE");       // Caps
  EXPECT_FALSE(hid_.Init(false));
  EXPECT_FALSE(hid_.Initialized());
}

TEST_F(U2FHidTest, InitBadNonce) {
  ExpectInit(false,              // Copy nonce
             "0000000000000000"  // Incorrect nonce (prepend to cid)
             "AABBCCDD",         // Cid
             "00000000",         // Version - too short!
             "DE");              // Caps
  EXPECT_FALSE(hid_.Init(false));
  EXPECT_FALSE(hid_.Initialized());
}

TEST_F(U2FHidTest, InitSendError) {
  EXPECT_CALL(device_, Open()).WillOnce(Return(true));
  EXPECT_CALL(device_, SendRequest(_, _, _)).WillOnce(Return(false));

  EXPECT_FALSE(hid_.Init(false));
  EXPECT_FALSE(hid_.Initialized());
}

TEST_F(U2FHidTest, InitRecvError) {
  EXPECT_CALL(device_, Open()).WillOnce(Return(true));
  EXPECT_CALL(device_,
              SendRequest(IsBroadcastCid(),
                          EqCommandCode(U2FHid::CommandCode::kInit), _))
      .WillOnce(Return(true));
  EXPECT_CALL(device_, RecvResponse(_, _, _, _)).WillOnce(Return(false));

  EXPECT_FALSE(hid_.Init(false));
  EXPECT_FALSE(hid_.Initialized());
}

TEST_F(U2FHidTest, Lock) {
  ExpectDefaultInit();
  EXPECT_TRUE(hid_.Init(false));

  ExpectMsg(U2FHid::CommandCode::kLock, false);
  EXPECT_TRUE(hid_.Lock(10));
}

TEST_F(U2FHidTest, Msg) {
  brillo::Blob request = {1, 2, 3, 4, 5};
  brillo::Blob response;

  ExpectDefaultInit();
  EXPECT_TRUE(hid_.Init(false));

  ExpectMsg(U2FHid::CommandCode::kMsg, true);
  EXPECT_TRUE(hid_.Msg(request, &response));
  EXPECT_THAT(response, ContainerEq(request));
}

TEST_F(U2FHidTest, Ping) {
  ExpectDefaultInit();
  EXPECT_TRUE(hid_.Init(false));

  ExpectMsg(U2FHid::CommandCode::kPing, true);
  EXPECT_TRUE(hid_.Ping(10));
}

TEST_F(U2FHidTest, Wink) {
  ExpectDefaultInit();
  EXPECT_TRUE(hid_.Init(false));

  ExpectMsg(U2FHid::CommandCode::kWink, true);
  EXPECT_TRUE(hid_.Wink());
}

class MockU2FHid : public U2FHid {
 public:
  MockU2FHid() : U2FHid(nullptr) {}
  MOCK_METHOD(bool, Msg, (const brillo::Blob&, brillo::Blob*), (override));
};

class U2FTest : public ::testing::Test {
 public:
  U2FTest() : u2f_(&u2f_hid_) {}
  U2FTest(const U2FTest&) = delete;
  U2FTest& operator=(const U2FTest&) = delete;

  ~U2FTest() override = default;

 protected:
  void RunRegisterExpectFail() {
    const brillo::Blob challenge(32, 0xaa);
    const brillo::Blob application(32, 0xbb);

    brillo::Blob public_key;
    brillo::Blob key_handle;
    brillo::Blob cert;

    EXPECT_FALSE(u2f_.Register(-1,  // Default P1
                               challenge, application,
                               false,  // G2F
                               &public_key, &key_handle, &cert));
  }

  void RunAuthenticateExpectFail() {
    const brillo::Blob challenge(32, 0xaa);
    const brillo::Blob application(32, 0xbb);
    const brillo::Blob key_handle(27, 0xde);

    bool presence_verified = false;
    brillo::Blob counter;
    brillo::Blob signature;

    EXPECT_FALSE(u2f_.Authenticate(-1,  // Default P1
                                   challenge, application, key_handle,
                                   &presence_verified, &counter, &signature));
  }

  MockU2FHid u2f_hid_;
  U2F u2f_;
};

TEST_F(U2FTest, RegisterSuccess) {
  const brillo::Blob expected_public_key(65, 0x65);
  const brillo::Blob expected_key_handle(13, 0xde);
  const brillo::Blob expected_cert(29, 0xfc);
  // See section 4.3 of U2F Raw Message Format spec
  // for details.
  brillo::Blob response = {
      0x05,  // Reserved (legacy reasons)
  };
  // Public key, fixed size.
  U2F::AppendBlob(expected_public_key, &response);
  // Key handle, variable size.
  response.push_back(expected_key_handle.size());
  U2F::AppendBlob(expected_key_handle, &response);
  // Cert and signature, variable size.
  U2F::AppendBlob(expected_cert, &response);
  // Status code: SW_NO_ERROR
  response.push_back(0x90);  // Sw1
  response.push_back(0x00);  // Sw2

  EXPECT_CALL(u2f_hid_, Msg(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(response), Return(true)));

  const brillo::Blob challenge(32, 0xaa);
  const brillo::Blob application(32, 0xbb);

  brillo::Blob public_key;
  brillo::Blob key_handle;
  brillo::Blob cert;

  EXPECT_TRUE(u2f_.Register(-1,  // Default P1
                            challenge, application,
                            false,  // G2F
                            &public_key, &key_handle, &cert));

  EXPECT_THAT(public_key, ContainerEq(expected_public_key));
  EXPECT_THAT(key_handle, ContainerEq(expected_key_handle));
  EXPECT_THAT(cert, ContainerEq(expected_cert));
}

TEST_F(U2FTest, RegisterMsgFails) {
  EXPECT_CALL(u2f_hid_, Msg(_, _)).WillOnce(Return(false));

  RunRegisterExpectFail();
}

TEST_F(U2FTest, RegisterBadStatus) {
  brillo::Blob response = {
      // Dummy data, unused.
      0xDE, 0xAD, 0xBE, 0xEF,
      // Status code: SW_WRONG_DATA
      0x6A,  // SW1
      0x80,  // SW2
  };

  EXPECT_CALL(u2f_hid_, Msg(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(response), Return(true)));

  RunRegisterExpectFail();
}

TEST_F(U2FTest, RegisterShortResponse) {
  // See section 4.3 of U2F Raw Message Format spec
  // for details.
  brillo::Blob response = {
      0x05,  // Reserved (legacy reasons)
      // Rest of response should go here (intentionally missing).
      // Status code: SW_NO_ERROR
      0x90,  // SW1
      0x00,  // SW2
  };

  EXPECT_CALL(u2f_hid_, Msg(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(response), Return(true)));

  RunRegisterExpectFail();
}

TEST_F(U2FTest, AuthenticateSuccess) {
  brillo::Blob response = {0x01,                    // Presence verified
                           0x01, 0x02, 0x03, 0x04,  // Counter
                           0xde, 0xad, 0xbe, 0xef,  // Signature
                           0x90, 0x00};             // Status code: SW_NO_ERROR

  EXPECT_CALL(u2f_hid_, Msg(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(response), Return(true)));

  const brillo::Blob challenge(32, 0xaa);
  const brillo::Blob application(32, 0xbb);
  const brillo::Blob key_handle(27, 0xde);

  bool presence_verified = false;
  brillo::Blob counter;
  brillo::Blob signature;

  EXPECT_TRUE(u2f_.Authenticate(-1,  // Default P1
                                challenge, application, key_handle,
                                &presence_verified, &counter, &signature));

  EXPECT_TRUE(presence_verified);
  EXPECT_THAT(counter, ElementsAre(1, 2, 3, 4));
  EXPECT_THAT(signature, ElementsAre(0xde, 0xad, 0xbe, 0xef));
}

TEST_F(U2FTest, AuthenticateMsgFail) {
  EXPECT_CALL(u2f_hid_, Msg(_, _)).WillOnce(Return(false));

  RunAuthenticateExpectFail();
}

TEST_F(U2FTest, AuthenticateBadStatus) {
  brillo::Blob response = {0x01,                    // Presence verified
                           0x01, 0x02, 0x03, 0x04,  // Counter
                           0xde, 0xad, 0xbe, 0xef,  // Signature
                           0x6A, 0x80};  // Status code: U2F_SW_NO_ERROR

  EXPECT_CALL(u2f_hid_, Msg(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(response), Return(true)));

  RunAuthenticateExpectFail();
}

TEST_F(U2FTest, AuthenticateShortReponse) {
  brillo::Blob response = {0x01,         // Presence verified
                                         // Remainder of response should go here
                                         // (intentionally left blank)
                           0x90, 0x00};  // Status code: SW_NO_ERROR

  EXPECT_CALL(u2f_hid_, Msg(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(response), Return(true)));

  RunAuthenticateExpectFail();
}

}  // namespace
}  // namespace g2f_client
