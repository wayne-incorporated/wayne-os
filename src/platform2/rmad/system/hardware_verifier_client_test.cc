// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/system/hardware_verifier_client_impl.h"

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/hardware_verifier/dbus-constants.h>
#include <gmock/gmock.h>
#include <google/protobuf/text_format.h>
#include <gtest/gtest.h>
#include <hardware_verifier/hardware_verifier.pb.h>
#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

#include "rmad/constants.h"

using testing::_;
using testing::Return;
using testing::StrictMock;

namespace {

constexpr char kVerifyComponentsReplyCompliant[] = R"(
  error: ERROR_OK
  hw_verification_report: {
    is_compliant: true
    found_component_infos: [
      {
        component_category: battery
        qualification_status: QUALIFIED
        component_fields: {
          battery: {
            manufacturer: "ABC"
            model_name: "abc"
          }
        }
      }
    ]
  }
)";

constexpr char kVerifyComponentsReplyNotCompliant[] = R"(
  error: ERROR_OK
  hw_verification_report: {
    is_compliant: false
    found_component_infos: [
      {
        component_category: battery
        qualification_status: UNQUALIFIED
        component_fields: {
          battery: {
            manufacturer: "ABC"
            model_name: "abc"
          }
        }
      },
      {
        component_category: storage
        qualification_status: QUALIFIED
        component_fields: {
          storage: {
            type: "MMC",
            mmc_manfid: 10
            mmc_name: "MmcName"
          }
        }
      },
      {
        component_category: camera
        qualification_status: REJECTED
        component_fields: {
          camera: {
            usb_vendor_id: 10
            usb_product_id: 11
          }
        }
      },
      {
        component_category: dram
        qualification_status: NO_MATCH
      }
    ]
  }
)";

constexpr std::array<const char*, 3> kVerifyComponentsErrorStrings = {
    "Unqualified battery: battery_ABC_abc",
    "Unqualified camera: camera_000a_000b",
    "Unqualified dram: unknown_component"};

constexpr char kVerifyComponentsReplyError[] = "error: ERROR_OTHER_ERROR";

}  // namespace

namespace rmad {

class HardwareVerifierClientTest : public testing::Test {
 public:
  HardwareVerifierClientTest()
      : mock_bus_(new StrictMock<dbus::MockBus>(dbus::Bus::Options())),
        mock_object_proxy_(new StrictMock<dbus::MockObjectProxy>(
            mock_bus_.get(),
            hardware_verifier::kHardwareVerifierServiceName,
            dbus::ObjectPath(
                hardware_verifier::kHardwareVerifierServicePath))) {}
  ~HardwareVerifierClientTest() override = default;

  void SetUp() override {
    EXPECT_CALL(
        *mock_bus_,
        GetObjectProxy(
            hardware_verifier::kHardwareVerifierServiceName,
            dbus::ObjectPath(hardware_verifier::kHardwareVerifierServicePath)))
        .WillOnce(Return(mock_object_proxy_.get()));
    hardware_verifier_client_ =
        std::make_unique<HardwareVerifierClientImpl>(mock_bus_);
  }

 protected:
  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> mock_object_proxy_;
  std::unique_ptr<HardwareVerifierClientImpl> hardware_verifier_client_;
};

TEST_F(HardwareVerifierClientTest, GetHardwareVerificationResult_Compliant) {
  EXPECT_CALL(*mock_object_proxy_, CallMethodAndBlock(_, _))
      .WillOnce([](dbus::MethodCall*, int) {
        std::unique_ptr<dbus::Response> hardware_verifier_response =
            dbus::Response::CreateEmpty();
        hardware_verifier::VerifyComponentsReply reply;
        CHECK(google::protobuf::TextFormat::ParseFromString(
            kVerifyComponentsReplyCompliant, &reply));
        dbus::MessageWriter writer(hardware_verifier_response.get());
        writer.AppendProtoAsArrayOfBytes(reply);
        return hardware_verifier_response;
      });

  bool is_compliant;
  std::vector<std::string> error_strings;
  EXPECT_TRUE(hardware_verifier_client_->GetHardwareVerificationResult(
      &is_compliant, &error_strings));
  EXPECT_TRUE(is_compliant);
  EXPECT_EQ(error_strings.size(), 0);
}

TEST_F(HardwareVerifierClientTest, GetHardwareVerificationResult_NotCompliant) {
  EXPECT_CALL(*mock_object_proxy_, CallMethodAndBlock(_, _))
      .WillOnce([](dbus::MethodCall*, int) {
        std::unique_ptr<dbus::Response> hardware_verifier_response =
            dbus::Response::CreateEmpty();
        hardware_verifier::VerifyComponentsReply reply;
        CHECK(google::protobuf::TextFormat::ParseFromString(
            kVerifyComponentsReplyNotCompliant, &reply));
        dbus::MessageWriter writer(hardware_verifier_response.get());
        writer.AppendProtoAsArrayOfBytes(reply);
        return hardware_verifier_response;
      });

  bool is_compliant;
  std::vector<std::string> error_strings;
  EXPECT_TRUE(hardware_verifier_client_->GetHardwareVerificationResult(
      &is_compliant, &error_strings));
  EXPECT_FALSE(is_compliant);
  EXPECT_EQ(error_strings.size(), 3);
  for (int i = 0; i < 3; ++i) {
    EXPECT_EQ(error_strings[i], kVerifyComponentsErrorStrings[i]);
  }
}

TEST_F(HardwareVerifierClientTest,
       GetHardwareVerificationResult_EmptyResponse) {
  EXPECT_CALL(*mock_object_proxy_, CallMethodAndBlock(_, _))
      .WillOnce(
          [](dbus::MethodCall*, int) { return dbus::Response::CreateEmpty(); });

  bool is_compliant;
  std::vector<std::string> error_strings;
  EXPECT_FALSE(hardware_verifier_client_->GetHardwareVerificationResult(
      &is_compliant, &error_strings));
}

TEST_F(HardwareVerifierClientTest,
       GetHardwareVerificationResult_ErrorResponse) {
  EXPECT_CALL(*mock_object_proxy_, CallMethodAndBlock(_, _))
      .WillOnce([](dbus::MethodCall*, int) {
        std::unique_ptr<dbus::Response> hardware_verifier_response =
            dbus::Response::CreateEmpty();
        hardware_verifier::VerifyComponentsReply reply;
        CHECK(google::protobuf::TextFormat::ParseFromString(
            kVerifyComponentsReplyError, &reply));
        dbus::MessageWriter writer(hardware_verifier_response.get());
        writer.AppendProtoAsArrayOfBytes(reply);
        return hardware_verifier_response;
      });

  bool is_compliant;
  std::vector<std::string> error_strings;
  EXPECT_FALSE(hardware_verifier_client_->GetHardwareVerificationResult(
      &is_compliant, &error_strings));
}

}  // namespace rmad
