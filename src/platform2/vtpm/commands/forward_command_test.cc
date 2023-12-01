// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/forward_command.h"

#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/mock_command_parser.h>
#include <trunks/mock_response_serializer.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/mock_password_changer.h"
#include "vtpm/backends/mock_static_analyzer.h"
#include "vtpm/backends/mock_tpm_handle_manager.h"
#include "vtpm/backends/scoped_host_key_handle.h"
#include "vtpm/backends/static_analyzer.h"
#include "vtpm/commands/mock_command.h"

namespace vtpm {

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Expectation;
using ::testing::Invoke;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;
using ::testing::WithArgs;

constexpr trunks::TPM_HANDLE kFakeVirtualHandle1 = 0x9487;
constexpr trunks::TPM_HANDLE kFakeVirtualHandle2 = 0x0806;
constexpr trunks::TPM_HANDLE kFakeHostHandle1 = 0x4262;
constexpr trunks::TPM_HANDLE kFakeHostHandle2 = 0xface;
constexpr char kFakeParam[] = "fake param";
constexpr char kTestResponse[] = "test response";
constexpr trunks::TPM_CC kFakeCC = 0x0449;

// Since `ForwardCommand` has the knowledge of TPM header size, the fake header
// has to be in the same size.
std::string GetFakeHeader() {
  std::string header;
  while (header.size() < trunks::kHeaderSize) {
    header += "header";
  }
  return header.substr(0, trunks::kHeaderSize);
}

std::string ToSerializedHandle(trunks::TPM_HANDLE h) {
  std::string s;
  trunks::Serialize_TPM_HANDLE(h, &s);
  return s;
}

}  // namespace

class ForwardCommandTest : public testing::Test {
 public:
  trunks::TPM_RC FakeTranslateHandle(trunks::TPM_HANDLE h,
                                     ScopedHostKeyHandle* host_handle) {
    trunks::TPM_HANDLE hh = 0;
    if (h == kFakeVirtualHandle1) {
      hh = kFakeHostHandle1;
    } else if (h == kFakeVirtualHandle2) {
      hh = kFakeHostHandle2;
    }
    *host_handle = ScopedHostKeyHandle(&this->mock_tpm_handle_manager_, hh, hh);
    return trunks::TPM_RC_SUCCESS;
  }

 protected:
  StrictMock<trunks::MockCommandParser> mock_cmd_parser_;
  StrictMock<trunks::MockResponseSerializer> mock_resp_serializer_;
  StrictMock<MockStaticAnalyzer> mock_static_analyzer_;
  StrictMock<MockTpmHandleManager> mock_tpm_handle_manager_;
  StrictMock<MockPasswordChanger> mock_password_changer_;
  StrictMock<MockCommand> mock_direct_forwarder_;
  ForwardCommand command_{&mock_cmd_parser_,       &mock_resp_serializer_,
                          &mock_static_analyzer_,  &mock_tpm_handle_manager_,
                          &mock_password_changer_, &mock_direct_forwarder_};
};

namespace {

TEST_F(ForwardCommandTest, SuccessOneHandle) {
  std::string fake_command = GetFakeHeader();
  fake_command += ToSerializedHandle(kFakeVirtualHandle1);
  fake_command += kFakeParam;

  EXPECT_CALL(mock_cmd_parser_, ParseHeader(Pointee(fake_command), _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeCC), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_static_analyzer_, GetCommandHandleCount(kFakeCC))
      .WillOnce(Return(1));

  EXPECT_CALL(mock_tpm_handle_manager_, TranslateHandle(kFakeVirtualHandle1, _))
      .WillOnce(Invoke(this, &ForwardCommandTest::FakeTranslateHandle));

  const std::string expected_host_command =
      GetFakeHeader() + ToSerializedHandle(kFakeHostHandle1) + kFakeParam;

  EXPECT_CALL(mock_password_changer_, Change(Eq(expected_host_command)))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  Expectation consume =
      EXPECT_CALL(mock_direct_forwarder_, Run(expected_host_command, _))
          .WillOnce(WithArgs<1>([](CommandResponseCallback callback) {
            std::move(callback).Run(kTestResponse);
          }));

  EXPECT_CALL(mock_tpm_handle_manager_, FlushHostHandle(kFakeHostHandle1))
      .After(consume);

  EXPECT_CALL(mock_static_analyzer_, IsSuccessfulResponse(kTestResponse))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_static_analyzer_, GetOperationContextType(kFakeCC))
      .WillOnce(Return(OperationContextType::kNone));

  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  command_.Run(fake_command, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(ForwardCommandTest, SuccessTwoHandles) {
  std::string fake_command = GetFakeHeader();
  fake_command += ToSerializedHandle(kFakeVirtualHandle1);
  fake_command += ToSerializedHandle(kFakeVirtualHandle2);
  fake_command += kFakeParam;

  EXPECT_CALL(mock_cmd_parser_, ParseHeader(Pointee(fake_command), _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeCC), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_static_analyzer_, GetCommandHandleCount(kFakeCC))
      .WillOnce(Return(2));

  EXPECT_CALL(mock_tpm_handle_manager_, TranslateHandle(kFakeVirtualHandle1, _))
      .WillOnce(Invoke(this, &ForwardCommandTest::FakeTranslateHandle));
  EXPECT_CALL(mock_tpm_handle_manager_, TranslateHandle(kFakeVirtualHandle2, _))
      .WillOnce(Invoke(this, &ForwardCommandTest::FakeTranslateHandle));

  const std::string expected_host_command =
      GetFakeHeader() + ToSerializedHandle(kFakeHostHandle1) +
      ToSerializedHandle(kFakeHostHandle2) + kFakeParam;

  EXPECT_CALL(mock_password_changer_, Change(Eq(expected_host_command)))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  Expectation consume =
      EXPECT_CALL(mock_direct_forwarder_, Run(expected_host_command, _))
          .WillOnce(WithArgs<1>([](CommandResponseCallback callback) {
            std::move(callback).Run(kTestResponse);
          }));

  EXPECT_CALL(mock_tpm_handle_manager_, FlushHostHandle(kFakeHostHandle1))
      .After(consume);
  EXPECT_CALL(mock_tpm_handle_manager_, FlushHostHandle(kFakeHostHandle2))
      .After(consume);

  EXPECT_CALL(mock_static_analyzer_, IsSuccessfulResponse(kTestResponse))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_static_analyzer_, GetOperationContextType(kFakeCC))
      .WillOnce(Return(OperationContextType::kNone));

  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  command_.Run(fake_command, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(ForwardCommandTest, SuccessNoHandle) {
  const std::string fake_command = GetFakeHeader() + kFakeParam;

  EXPECT_CALL(mock_cmd_parser_, ParseHeader(Pointee(fake_command), _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeCC), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_static_analyzer_, GetCommandHandleCount(kFakeCC))
      .WillOnce(Return(0));

  EXPECT_CALL(mock_password_changer_, Change(Eq(fake_command)))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(mock_direct_forwarder_, Run(fake_command, _))
      .WillOnce(WithArgs<1>([](CommandResponseCallback callback) {
        std::move(callback).Run(kTestResponse);
      }));

  EXPECT_CALL(mock_static_analyzer_, IsSuccessfulResponse(kTestResponse))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_static_analyzer_, GetOperationContextType(kFakeCC))
      .WillOnce(Return(OperationContextType::kNone));

  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  command_.Run(fake_command, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(ForwardCommandTest, FailureSecondTranslation) {
  std::string fake_command = GetFakeHeader();
  fake_command += ToSerializedHandle(kFakeVirtualHandle1);
  fake_command += ToSerializedHandle(kFakeVirtualHandle2);
  fake_command += kFakeParam;

  EXPECT_CALL(mock_cmd_parser_, ParseHeader(Pointee(fake_command), _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeCC), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_static_analyzer_, GetCommandHandleCount(kFakeCC))
      .WillOnce(Return(2));

  EXPECT_CALL(mock_tpm_handle_manager_, TranslateHandle(kFakeVirtualHandle1, _))
      .WillOnce(Invoke(this, &ForwardCommandTest::FakeTranslateHandle));
  EXPECT_CALL(mock_tpm_handle_manager_, TranslateHandle(kFakeVirtualHandle2, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_FAILURE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  // Ensure no resource leak.
  EXPECT_CALL(mock_tpm_handle_manager_, FlushHostHandle(kFakeHostHandle1));

  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  command_.Run(fake_command, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(ForwardCommandTest, FailureErrorChangingPassword) {
  const std::string fake_command = GetFakeHeader() + kFakeParam;

  EXPECT_CALL(mock_cmd_parser_, ParseHeader(Pointee(fake_command), _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeCC), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_static_analyzer_, GetCommandHandleCount(kFakeCC))
      .WillOnce(Return(0));

  EXPECT_CALL(mock_password_changer_, Change(Eq(fake_command)))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_FAILURE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  command_.Run(fake_command, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(ForwardCommandTest, FailureHeaderError) {
  std::string fake_command = GetFakeHeader();
  fake_command += ToSerializedHandle(kFakeVirtualHandle1);
  fake_command += ToSerializedHandle(kFakeVirtualHandle2);
  fake_command += kFakeParam;

  EXPECT_CALL(mock_cmd_parser_, ParseHeader(Pointee(fake_command), _, _, _))
      .WillOnce(Return(trunks::TPM_RC_INSUFFICIENT));

  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_INSUFFICIENT, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  command_.Run(fake_command, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(ForwardCommandTest, SuccessOneHandleUnsuccessfulTpmOperation) {
  std::string fake_command = GetFakeHeader();
  fake_command += ToSerializedHandle(kFakeVirtualHandle1);
  fake_command += kFakeParam;

  EXPECT_CALL(mock_cmd_parser_, ParseHeader(Pointee(fake_command), _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeCC), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_static_analyzer_, GetCommandHandleCount(kFakeCC))
      .WillOnce(Return(1));

  EXPECT_CALL(mock_tpm_handle_manager_, TranslateHandle(kFakeVirtualHandle1, _))
      .WillOnce(Invoke(this, &ForwardCommandTest::FakeTranslateHandle));

  const std::string expected_host_command =
      GetFakeHeader() + ToSerializedHandle(kFakeHostHandle1) + kFakeParam;

  EXPECT_CALL(mock_password_changer_, Change(Eq(expected_host_command)))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  Expectation consume =
      EXPECT_CALL(mock_direct_forwarder_, Run(expected_host_command, _))
          .WillOnce(WithArgs<1>([](CommandResponseCallback callback) {
            std::move(callback).Run(kTestResponse);
          }));

  EXPECT_CALL(mock_tpm_handle_manager_, FlushHostHandle(kFakeHostHandle1))
      .After(consume);

  EXPECT_CALL(mock_static_analyzer_, IsSuccessfulResponse(kTestResponse))
      .WillOnce(Return(false));

  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  command_.Run(fake_command, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(ForwardCommandTest, SuccessOneHandleWithLoad) {
  std::string fake_command = GetFakeHeader();
  fake_command += ToSerializedHandle(kFakeVirtualHandle1);
  fake_command += kFakeParam;

  EXPECT_CALL(mock_cmd_parser_, ParseHeader(Pointee(fake_command), _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeCC), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_static_analyzer_, GetCommandHandleCount(kFakeCC))
      .WillOnce(Return(1));

  EXPECT_CALL(mock_tpm_handle_manager_, TranslateHandle(kFakeVirtualHandle1, _))
      .WillOnce(Invoke(this, &ForwardCommandTest::FakeTranslateHandle));

  const std::string expected_host_command =
      GetFakeHeader() + ToSerializedHandle(kFakeHostHandle1) + kFakeParam;

  EXPECT_CALL(mock_password_changer_, Change(Eq(expected_host_command)))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  Expectation consume =
      EXPECT_CALL(mock_direct_forwarder_, Run(expected_host_command, _))
          .WillOnce(WithArgs<1>([](CommandResponseCallback callback) {
            std::move(callback).Run(kTestResponse);
          }));

  EXPECT_CALL(mock_tpm_handle_manager_, FlushHostHandle(kFakeHostHandle1))
      .After(consume);

  EXPECT_CALL(mock_static_analyzer_, IsSuccessfulResponse(kTestResponse))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_static_analyzer_, GetOperationContextType(kFakeCC))
      .WillOnce(Return(OperationContextType::kLoad));
  EXPECT_CALL(mock_tpm_handle_manager_, OnLoad(_, _));

  // To satisfy the assertion we have; it doesn't matter if it is calls or not.
  EXPECT_CALL(mock_static_analyzer_, GetResponseHandleCount(kFakeCC))
      .WillRepeatedly(Return(1));

  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  command_.Run(fake_command, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(ForwardCommandTest, SuccessOneHandleWithUnload) {
  std::string fake_command = GetFakeHeader();
  fake_command += ToSerializedHandle(kFakeVirtualHandle1);
  fake_command += kFakeParam;

  EXPECT_CALL(mock_cmd_parser_, ParseHeader(Pointee(fake_command), _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeCC), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_static_analyzer_, GetCommandHandleCount(kFakeCC))
      .WillOnce(Return(1));

  EXPECT_CALL(mock_tpm_handle_manager_, TranslateHandle(kFakeVirtualHandle1, _))
      .WillOnce(Invoke(this, &ForwardCommandTest::FakeTranslateHandle));

  const std::string expected_host_command =
      GetFakeHeader() + ToSerializedHandle(kFakeHostHandle1) + kFakeParam;

  EXPECT_CALL(mock_password_changer_, Change(Eq(expected_host_command)))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  Expectation consume =
      EXPECT_CALL(mock_direct_forwarder_, Run(expected_host_command, _))
          .WillOnce(WithArgs<1>([](CommandResponseCallback callback) {
            std::move(callback).Run(kTestResponse);
          }));

  EXPECT_CALL(mock_tpm_handle_manager_, FlushHostHandle(kFakeHostHandle1))
      .After(consume);

  EXPECT_CALL(mock_static_analyzer_, IsSuccessfulResponse(kTestResponse))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_static_analyzer_, GetOperationContextType(kFakeCC))
      .WillOnce(Return(OperationContextType::kUnload));
  EXPECT_CALL(mock_tpm_handle_manager_, OnUnload(_));

  // To satisfy the assertion we have; it doesn't matter if it is calls or not.
  EXPECT_CALL(mock_static_analyzer_, GetResponseHandleCount(kFakeCC))
      .WillRepeatedly(Return(1));

  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  command_.Run(fake_command, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

}  // namespace

}  // namespace vtpm
