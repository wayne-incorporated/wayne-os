// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <memory>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_object.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "easy-unlock/dbus_adaptor.h"
#include "easy-unlock/fake_easy_unlock_service.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::Return;

namespace {

class MethodCallHandlers {
 public:
  typedef base::RepeatingCallback<void(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender sender)>
      Handler;

  MethodCallHandlers() {}
  MethodCallHandlers(const MethodCallHandlers&) = delete;
  MethodCallHandlers& operator=(const MethodCallHandlers&) = delete;

  ~MethodCallHandlers() {}

  void SetGenerateEcP256KeyPairHandler(
      const std::string& interface,
      const std::string& method,
      Handler handler,
      dbus::ExportedObject::OnExportedCallback export_handler) {
    generate_ec_p256_key_pair_handler_ = handler;
    std::move(export_handler).Run(interface, method, true);
  }

  void SetWrapPublicKeyHandler(
      const std::string& interface,
      const std::string& method,
      Handler handler,
      dbus::ExportedObject::OnExportedCallback export_handler) {
    wrap_public_key_handler_ = handler;
    std::move(export_handler).Run(interface, method, true);
  }

  void SetPerformECDHKeyAgreementHandler(
      const std::string& interface,
      const std::string& method,
      Handler handler,
      dbus::ExportedObject::OnExportedCallback export_handler) {
    perform_ecdh_key_agreement_handler_ = handler;
    std::move(export_handler).Run(interface, method, true);
  }

  void SetCreateSecureMessageHandler(
      const std::string& interface,
      const std::string& method,
      Handler handler,
      dbus::ExportedObject::OnExportedCallback export_handler) {
    create_secure_message_handler_ = handler;
    std::move(export_handler).Run(interface, method, true);
  }

  void SetUnwrapSecureMessageHandler(
      const std::string& interface,
      const std::string& method,
      Handler handler,
      dbus::ExportedObject::OnExportedCallback export_handler) {
    unwrap_secure_message_handler_ = handler;
    std::move(export_handler).Run(interface, method, true);
  }

  void CallGenerateEcP256KeyPair(dbus::MethodCall* method_call,
                                 dbus::ExportedObject::ResponseSender sender) {
    ASSERT_FALSE(generate_ec_p256_key_pair_handler_.is_null());
    generate_ec_p256_key_pair_handler_.Run(method_call, std::move(sender));
  }

  void CallWrapPublicKey(dbus::MethodCall* method_call,
                         dbus::ExportedObject::ResponseSender sender) {
    ASSERT_FALSE(wrap_public_key_handler_.is_null());
    wrap_public_key_handler_.Run(method_call, std::move(sender));
  }

  void CallPerformECDHKeyAgreement(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender sender) {
    ASSERT_FALSE(perform_ecdh_key_agreement_handler_.is_null());
    perform_ecdh_key_agreement_handler_.Run(method_call, std::move(sender));
  }

  void CallCreateSecureMessage(dbus::MethodCall* method_call,
                               dbus::ExportedObject::ResponseSender sender) {
    ASSERT_FALSE(create_secure_message_handler_.is_null());
    create_secure_message_handler_.Run(method_call, std::move(sender));
  }

  void CallUnwrapSecureMessage(dbus::MethodCall* method_call,
                               dbus::ExportedObject::ResponseSender sender) {
    ASSERT_FALSE(unwrap_secure_message_handler_.is_null());
    unwrap_secure_message_handler_.Run(method_call, std::move(sender));
  }

 private:
  Handler generate_ec_p256_key_pair_handler_;
  Handler wrap_public_key_handler_;
  Handler perform_ecdh_key_agreement_handler_;
  Handler create_secure_message_handler_;
  Handler unwrap_secure_message_handler_;
};

class EasyUnlockTest : public ::testing::Test {
 public:
  EasyUnlockTest()
      : method_call_handlers_(new MethodCallHandlers()),
        service_path_(easy_unlock::kEasyUnlockServicePath) {}
  virtual ~EasyUnlockTest() {}

  virtual void SetUp() {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::MockBus(options);

    SetUpExportedObject();

    service_impl_.reset(new easy_unlock::FakeService());

    adaptor_.reset(new easy_unlock::DBusAdaptor(bus_, service_impl_.get()));
    adaptor_->Register(
        brillo::dbus_utils::AsyncEventSequencer::GetDefaultCompletionAction());
  }

  virtual void TearDown() {}

  void VerifyGenerateEcP256KeyPairResponse(
      std::unique_ptr<dbus::Response> response) {
    ASSERT_TRUE(response.get());

    dbus::MessageReader reader(response.get());

    const uint8_t* bytes = nullptr;
    size_t length = 0;

    ASSERT_TRUE(reader.PopArrayOfBytes(&bytes, &length));
    ASSERT_EQ("private_key_1",
              std::string(reinterpret_cast<const char*>(bytes), length));

    ASSERT_TRUE(reader.PopArrayOfBytes(&bytes, &length));
    ASSERT_EQ("public_key_1",
              std::string(reinterpret_cast<const char*>(bytes), length));
  }

  void VerifyDataResponse(const std::string& expected_content,
                          std::unique_ptr<dbus::Response> response) {
    ASSERT_TRUE(response.get());

    dbus::MessageReader reader(response.get());

    const uint8_t* bytes = nullptr;
    size_t length = 0;

    ASSERT_TRUE(reader.PopArrayOfBytes(&bytes, &length));
    ASSERT_EQ(expected_content,
              std::string(reinterpret_cast<const char*>(bytes), length));
  }

  void VerifyNoDataResponse(std::unique_ptr<dbus::Response> response) {
    ASSERT_TRUE(response.get());
    dbus::MessageReader reader(response.get());
    const uint8_t* bytes = nullptr;
    size_t length = 0;

    // Client handles both of these cases the same (response not being set to
    // a byte array, and response being empty byte array).
    bool hasData = reader.PopArrayOfBytes(&bytes, &length);
    if (hasData)
      EXPECT_EQ(0u, length);
  }

 protected:
  std::unique_ptr<MethodCallHandlers> method_call_handlers_;

 private:
  void SetUpExportedObject() {
    ASSERT_TRUE(bus_.get());

    // Create a mock exported object that behaves as
    // org.chromium.EasyUnlock DBus service.
    exported_object_ = new dbus::MockExportedObject(bus_.get(), service_path_);

    EXPECT_CALL(*bus_, GetExportedObject(service_path_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(exported_object_.get()));

    EXPECT_CALL(*exported_object_, ExportMethod(_, _, _, _)).Times(AnyNumber());

    EXPECT_CALL(*exported_object_,
                ExportMethod(easy_unlock::kEasyUnlockServiceInterface,
                             easy_unlock::kGenerateEcP256KeyPairMethod, _, _))
        .WillOnce(Invoke(method_call_handlers_.get(),
                         &MethodCallHandlers::SetGenerateEcP256KeyPairHandler));
    EXPECT_CALL(*exported_object_,
                ExportMethod(easy_unlock::kEasyUnlockServiceInterface,
                             easy_unlock::kWrapPublicKeyMethod, _, _))
        .WillOnce(Invoke(method_call_handlers_.get(),
                         &MethodCallHandlers::SetWrapPublicKeyHandler));
    EXPECT_CALL(*exported_object_,
                ExportMethod(easy_unlock::kEasyUnlockServiceInterface,
                             easy_unlock::kPerformECDHKeyAgreementMethod, _, _))
        .WillOnce(
            Invoke(method_call_handlers_.get(),
                   &MethodCallHandlers::SetPerformECDHKeyAgreementHandler));
    EXPECT_CALL(*exported_object_,
                ExportMethod(easy_unlock::kEasyUnlockServiceInterface,
                             easy_unlock::kCreateSecureMessageMethod, _, _))
        .WillOnce(Invoke(method_call_handlers_.get(),
                         &MethodCallHandlers::SetCreateSecureMessageHandler));
    EXPECT_CALL(*exported_object_,
                ExportMethod(easy_unlock::kEasyUnlockServiceInterface,
                             easy_unlock::kUnwrapSecureMessageMethod, _, _))
        .WillOnce(Invoke(method_call_handlers_.get(),
                         &MethodCallHandlers::SetUnwrapSecureMessageHandler));
  }

  const dbus::ObjectPath service_path_;

  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockExportedObject> exported_object_;

  std::unique_ptr<easy_unlock::Service> service_impl_;
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  std::unique_ptr<easy_unlock::DBusAdaptor> adaptor_;
};

TEST_F(EasyUnlockTest, GenerateEcP256KeyPair) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kGenerateEcP256KeyPairMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);
  method_call_handlers_->CallGenerateEcP256KeyPair(
      &method_call,
      base::BindOnce(&EasyUnlockTest::VerifyGenerateEcP256KeyPairResponse,
                     base::Unretained(this)));
}

TEST_F(EasyUnlockTest, WrapPublicKeyRSA) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kWrapPublicKeyMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);

  const std::string public_key = "key";

  dbus::MessageWriter writer(&method_call);
  writer.AppendString(easy_unlock::kKeyAlgorithmRSA);
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(public_key.data()),
                            public_key.length());
  method_call_handlers_->CallWrapPublicKey(
      &method_call,
      base::BindOnce(&EasyUnlockTest::VerifyDataResponse,
                     base::Unretained(this), "public_key_RSA_key"));
}

TEST_F(EasyUnlockTest, WrapPublicKeyRSA_IUnvalid_UnknownAlgorithm) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kWrapPublicKeyMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);

  const std::string public_key = "key";

  dbus::MessageWriter writer(&method_call);
  writer.AppendString("UNKNOWN");
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(public_key.data()),
                            public_key.length());
  method_call_handlers_->CallWrapPublicKey(
      &method_call, base::BindOnce(&EasyUnlockTest::VerifyNoDataResponse,
                                   base::Unretained(this)));
}

TEST_F(EasyUnlockTest, PerformECDHKeyAgreement) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kPerformECDHKeyAgreementMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);

  const std::string private_key = "private_key_1";
  const std::string public_key = "public_key_2";

  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(private_key.data()),
      private_key.length());
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(public_key.data()),
                            public_key.length());

  method_call_handlers_->CallPerformECDHKeyAgreement(
      &method_call,
      base::BindOnce(
          &EasyUnlockTest::VerifyDataResponse, base::Unretained(this),
          "secret_key:{private_key:private_key_1,public_key:public_key_2}"));
}

TEST_F(EasyUnlockTest, CreateSecureMessage) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kCreateSecureMessageMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);

  const std::string payload = "cleartext message";
  const std::string key = "secret key";
  const std::string associated_data = "ad";
  const std::string public_metadata = "pm";
  const std::string verification_key_id = "key";
  const std::string decryption_key_id = "key1";

  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(payload.data()),
                            payload.length());
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(key.data()),
                            key.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(associated_data.data()),
      associated_data.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(public_metadata.data()),
      public_metadata.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(verification_key_id.data()),
      verification_key_id.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(decryption_key_id.data()),
      decryption_key_id.length());
  writer.AppendString(easy_unlock::kEncryptionTypeAES256CBC);
  writer.AppendString(easy_unlock::kSignatureTypeHMACSHA256);

  const std::string expected_response =
      "securemessage:{"
      "payload:cleartext message,"
      "key:secret key,"
      "associated_data:ad,"
      "public_metadata:pm,"
      "verification_key_id:key,"
      "decryption_key_id:key1,"
      "encryption:AES,"
      "signature:HMAC"
      "}";

  method_call_handlers_->CallCreateSecureMessage(
      &method_call, base::BindOnce(&EasyUnlockTest::VerifyDataResponse,
                                   base::Unretained(this), expected_response));
}

TEST_F(EasyUnlockTest, CreateSecureMessage_Invalid_MissingParameter) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kCreateSecureMessageMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);

  const std::string payload = "cleartext message";
  const std::string key = "secret key";
  const std::string associated_data = "ad";
  const std::string verification_key_id = "key";
  const std::string decryption_key_id = "key1";

  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(payload.data()),
                            payload.length());
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(key.data()),
                            key.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(associated_data.data()),
      associated_data.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(verification_key_id.data()),
      verification_key_id.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(decryption_key_id.data()),
      decryption_key_id.length());
  writer.AppendString(easy_unlock::kEncryptionTypeAES256CBC);
  writer.AppendString(easy_unlock::kSignatureTypeHMACSHA256);

  method_call_handlers_->CallCreateSecureMessage(
      &method_call, base::BindOnce(&EasyUnlockTest::VerifyNoDataResponse,
                                   base::Unretained(this)));
}

TEST_F(EasyUnlockTest, CreateSecureMessage_Invalid_UnknownEncryptionType) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kCreateSecureMessageMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);

  const std::string payload = "cleartext message";
  const std::string key = "secret key";
  const std::string associated_data = "ad";
  const std::string public_metadata = "pm";
  const std::string verification_key_id = "key";
  const std::string decryption_key_id = "key1";

  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(payload.data()),
                            payload.length());
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(key.data()),
                            key.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(associated_data.data()),
      associated_data.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(public_metadata.data()),
      public_metadata.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(verification_key_id.data()),
      verification_key_id.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(decryption_key_id.data()),
      decryption_key_id.length());
  writer.AppendString("UNKNOWN");
  writer.AppendString(easy_unlock::kSignatureTypeHMACSHA256);

  method_call_handlers_->CallCreateSecureMessage(
      &method_call, base::BindOnce(&EasyUnlockTest::VerifyNoDataResponse,
                                   base::Unretained(this)));
}

TEST_F(EasyUnlockTest, CreateSecureMessage_Invalid_UnknownSignatureType) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kCreateSecureMessageMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);

  const std::string payload = "cleartext message";
  const std::string key = "secret key";
  const std::string associated_data = "ad";
  const std::string public_metadata = "pm";
  const std::string verification_key_id = "key";
  const std::string decryption_key_id = "key1";

  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(payload.data()),
                            payload.length());
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(key.data()),
                            key.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(associated_data.data()),
      associated_data.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(public_metadata.data()),
      public_metadata.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(verification_key_id.data()),
      verification_key_id.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(decryption_key_id.data()),
      decryption_key_id.length());
  writer.AppendString(easy_unlock::kEncryptionTypeAES256CBC);
  writer.AppendString("UNKOWN");

  method_call_handlers_->CallCreateSecureMessage(
      &method_call, base::BindOnce(&EasyUnlockTest::VerifyNoDataResponse,
                                   base::Unretained(this)));
}

TEST_F(EasyUnlockTest, UnwrapSecureMessage) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kUnwrapSecureMessageMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);

  const std::string message = "secure message";
  const std::string key = "secret key";
  const std::string associated_data = "ad";

  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(message.data()),
                            message.length());
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(key.data()),
                            key.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(associated_data.data()),
      associated_data.length());
  writer.AppendString(easy_unlock::kEncryptionTypeAES256CBC);
  writer.AppendString(easy_unlock::kSignatureTypeHMACSHA256);

  const std::string expected_response =
      "unwrappedmessage:{"
      "original:secure message,"
      "key:secret key,"
      "associated_data:ad,"
      "encryption:AES,"
      "signature:HMAC"
      "}";

  method_call_handlers_->CallUnwrapSecureMessage(
      &method_call, base::BindOnce(&EasyUnlockTest::VerifyDataResponse,
                                   base::Unretained(this), expected_response));
}

TEST_F(EasyUnlockTest, UnwrapSecureMessage_Invalid_UnknownEncryptionType) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kUnwrapSecureMessageMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);

  const std::string message = "secure message";
  const std::string key = "secret key";
  const std::string associated_data = "ad";

  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(message.data()),
                            message.length());
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(key.data()),
                            key.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(associated_data.data()),
      associated_data.length());
  writer.AppendString("UNKNOWN");
  writer.AppendString(easy_unlock::kSignatureTypeHMACSHA256);

  method_call_handlers_->CallUnwrapSecureMessage(
      &method_call, base::BindOnce(&EasyUnlockTest::VerifyNoDataResponse,
                                   base::Unretained(this)));
}

TEST_F(EasyUnlockTest, UnwrapSecureMessage_Invalid_UnknownSignatureType) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kUnwrapSecureMessageMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);

  const std::string message = "secure message";
  const std::string key = "secret key";
  const std::string associated_data = "ad";

  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(message.data()),
                            message.length());
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(key.data()),
                            key.length());
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(associated_data.data()),
      associated_data.length());
  writer.AppendString(easy_unlock::kEncryptionTypeAES256CBC);
  writer.AppendString("UNKNOWN");

  method_call_handlers_->CallUnwrapSecureMessage(
      &method_call, base::BindOnce(&EasyUnlockTest::VerifyNoDataResponse,
                                   base::Unretained(this)));
}

TEST_F(EasyUnlockTest, UnwrapSecureMessage_Invalid_MissingParam) {
  dbus::MethodCall method_call(easy_unlock::kEasyUnlockServiceInterface,
                               easy_unlock::kUnwrapSecureMessageMethod);
  // Set serial to an arbitrary value.
  method_call.SetSerial(231);

  const std::string message = "secure message";
  const std::string key = "secret key";

  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(message.data()),
                            message.length());
  writer.AppendArrayOfBytes(reinterpret_cast<const uint8_t*>(key.data()),
                            key.length());
  writer.AppendString(easy_unlock::kEncryptionTypeAES256CBC);
  writer.AppendString(easy_unlock::kSignatureTypeHMACSHA256);

  method_call_handlers_->CallUnwrapSecureMessage(
      &method_call, base::BindOnce(&EasyUnlockTest::VerifyNoDataResponse,
                                   base::Unretained(this)));
}

}  // namespace
