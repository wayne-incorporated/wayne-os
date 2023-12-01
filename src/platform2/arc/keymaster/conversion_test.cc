// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/conversion.h"

#include <array>
#include <memory>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "arc/keymaster/keymaster_logger.h"

namespace arc {
namespace keymaster {

namespace {

KeymasterLogger logger;

constexpr std::array<uint8_t, 3> kBlob1{{0, 42, 55}};
constexpr std::array<uint8_t, 4> kBlob2{{251, 151, 101, 71}};
constexpr std::array<uint8_t, 5> kBlob3{{1, 2, 3, 4, 5}};

::testing::AssertionResult VerifyVectorUint8(const uint8_t* a,
                                             const size_t a_size,
                                             const std::vector<uint8_t>& b) {
  if (a_size != b.size()) {
    return ::testing::AssertionFailure()
           << "Sizes differ: a=" << a_size << " b=" << b.size();
  }
  for (size_t i = 0; i < a_size; ++i) {
    if (a[i] != b[i]) {
      return ::testing::AssertionFailure()
             << "Elements differ: a=" << static_cast<int>(a[i])
             << " b=" << static_cast<int>(b[i]);
    }
  }
  return ::testing::AssertionSuccess();
}

::testing::AssertionResult VerifyKeyParameters(
    const ::keymaster::AuthorizationSet& a,
    const std::vector<arc::mojom::KeyParameterPtr>& b) {
  if (a.size() != b.size()) {
    return ::testing::AssertionFailure()
           << "Sizes differ: a=" << a.size() << " b=" << b.size();
  }

  for (size_t i = 0; i < a.size(); ++i) {
    if (a[i].tag != b[i]->tag) {
      return ::testing::AssertionFailure()
             << "Tags differ: i=" << i
             << " a=" << static_cast<uint32_t>(a[i].tag) << " b=" << b[i]->tag;
    }
  }
  if (!(b[0]->param->is_boolean_value() && b[1]->param->is_integer() &&
        b[2]->param->is_long_integer() && b[3]->param->is_date_time() &&
        b[4]->param->is_blob()))
    return ::testing::AssertionFailure() << "Incorrect union value type";
  if (!(a[0].boolean == b[0]->param->get_boolean_value() &&
        a[1].integer == b[1]->param->get_integer() &&
        a[2].long_integer == b[2]->param->get_long_integer() &&
        a[3].date_time == b[3]->param->get_date_time()))
    return ::testing::AssertionFailure() << "Values differ";
  return VerifyVectorUint8(a[4].blob.data, a[4].blob.data_length,
                           b[4]->param->get_blob());
}

std::vector<arc::mojom::KeyParameterPtr> KeyParameterVector() {
  std::vector<arc::mojom::KeyParameterPtr> parameters(5);
  // bool
  auto paramBool = arc::mojom::IntegerKeyParam::NewBooleanValue(true);
  parameters[0] =
      arc::mojom::KeyParameter::New(KM_TAG_CALLER_NONCE, std::move(paramBool));
  // enum, enum_rep, int, int_rep
  auto paramInt =
      arc::mojom::IntegerKeyParam::NewInteger(KM_ALGORITHM_TRIPLE_DES);
  parameters[1] =
      arc::mojom::KeyParameter::New(KM_TAG_ALGORITHM, std::move(paramInt));
  // long
  auto paramLong = arc::mojom::IntegerKeyParam::NewLongInteger(65537);
  parameters[2] = arc::mojom::KeyParameter::New(KM_TAG_RSA_PUBLIC_EXPONENT,
                                                std::move(paramLong));
  // date
  auto paramDate = arc::mojom::IntegerKeyParam::NewDateTime(1337);
  parameters[3] = arc::mojom::KeyParameter::New(KM_TAG_ACTIVE_DATETIME,
                                                std::move(paramDate));
  // bignum, bytes
  auto paramBlob = arc::mojom::IntegerKeyParam::NewBlob(
      std::vector<uint8_t>(kBlob1.begin(), kBlob1.end()));
  parameters[4] = arc::mojom::KeyParameter::New(KM_TAG_APPLICATION_DATA,
                                                std::move(paramBlob));
  return parameters;
}

}  // namespace

TEST(ConvertToMojo, Uint8Vector) {
  // Convert.
  std::vector<uint8_t> output = ConvertToMojo(kBlob1.data(), kBlob1.size());

  // Verify.
  EXPECT_TRUE(VerifyVectorUint8(kBlob1.data(), kBlob1.size(), output));
}

TEST(ConvertToMojo, KeyParameterVector) {
  // Prepare.
  ::keymaster::AuthorizationSet input;
  input.push_back(keymaster_param_bool(KM_TAG_CALLER_NONCE));  // bool
  input.push_back(keymaster_param_enum(
      KM_TAG_ALGORITHM,
      KM_ALGORITHM_TRIPLE_DES));  // enum, enum_rep, int, int_rep
  input.push_back(
      keymaster_param_long(KM_TAG_RSA_PUBLIC_EXPONENT, 65537));         // long
  input.push_back(keymaster_param_date(KM_TAG_ACTIVE_DATETIME, 1337));  // date
  input.push_back(keymaster_param_blob(KM_TAG_APPLICATION_DATA, kBlob1.data(),
                                       kBlob1.size()));  // bignum, bytes

  // Convert.
  std::vector<arc::mojom::KeyParameterPtr> output = ConvertToMojo(input);

  // Verify.
  EXPECT_TRUE(VerifyKeyParameters(input, output));
}

TEST(ConvertToMessage, Buffer) {
  // Prepare.
  std::vector<uint8_t> input(kBlob1.begin(), kBlob1.end());

  // Convert.
  ::keymaster::Buffer buffer;
  ConvertToMessage(input, &buffer);
  uint8_t output[kBlob1.size()];

  // Verify.
  EXPECT_TRUE(buffer.read(output, input.size()));
  EXPECT_TRUE(VerifyVectorUint8(output, input.size(), input));
}

TEST(ConvertToMessage, ReusedBuffer) {
  // Prepare.
  std::vector<uint8_t> input1(kBlob1.begin(), kBlob1.end());
  std::vector<uint8_t> input2(kBlob2.begin(), kBlob2.end());

  // Convert.
  ::keymaster::Buffer buffer;
  ConvertToMessage(input1, &buffer);
  ConvertToMessage(input2, &buffer);
  uint8_t output[kBlob2.size()];

  // Verify.
  EXPECT_TRUE(buffer.read(output, kBlob2.size()));
  EXPECT_TRUE(VerifyVectorUint8(output, kBlob2.size(), input2));
}

TEST(ConvertToMessage, ClientIdAndAppData) {
  // Prepare.
  std::vector<uint8_t> clientId(kBlob1.begin(), kBlob1.end());
  std::vector<uint8_t> appData(kBlob2.begin(), kBlob2.end());

  // Convert.
  ::keymaster::AuthorizationSet output;
  ConvertToMessage(clientId, appData, &output);

  // Verify.
  ASSERT_EQ(2, output.size());
  EXPECT_EQ(KM_TAG_APPLICATION_ID, output[0].tag);
  EXPECT_EQ(KM_TAG_APPLICATION_DATA, output[1].tag);
  EXPECT_TRUE(VerifyVectorUint8(output[0].blob.data, output[0].blob.data_length,
                                clientId));
  EXPECT_TRUE(VerifyVectorUint8(output[1].blob.data, output[1].blob.data_length,
                                appData));
}

TEST(ConvertToMessage, GetKeyCharacteristicsRequest) {
  // Prepare.
  auto input = ::arc::mojom::GetKeyCharacteristicsRequest::New(
      std::vector<uint8_t>(kBlob1.begin(), kBlob1.end()),
      std::vector<uint8_t>(kBlob2.begin(), kBlob2.end()),
      std::vector<uint8_t>(kBlob3.begin(), kBlob3.end()));

  // Convert.
  auto output = MakeGetKeyCharacteristicsRequest(input);

  // Verify.
  EXPECT_TRUE(VerifyVectorUint8(output->key_blob.key_material,
                                output->key_blob.key_material_size,
                                input->key_blob));
  ASSERT_EQ(output->additional_params.size(), 2);
  EXPECT_TRUE(VerifyVectorUint8(output->additional_params[0].blob.data,
                                output->additional_params[0].blob.data_length,
                                input->client_id));
  EXPECT_TRUE(VerifyVectorUint8(output->additional_params[1].blob.data,
                                output->additional_params[1].blob.data_length,
                                input->app_data));
}

TEST(ConvertToMessage, GenerateKeyRequest) {
  // Prepare.
  std::vector<arc::mojom::KeyParameterPtr> input = KeyParameterVector();

  // Convert.
  auto output = MakeGenerateKeyRequest(input);

  // Verify.
  EXPECT_TRUE(VerifyKeyParameters(output->key_description, input));
}

TEST(ConvertToMessage, ImportKeyRequest) {
  // Prepare.
  auto input = arc::mojom::ImportKeyRequest::New(
      KeyParameterVector(), arc::mojom::KeyFormat::PKCS8,
      std::vector<uint8_t>(kBlob1.begin(), kBlob1.end()));

  // Convert.
  auto output = MakeImportKeyRequest(std::move(input));

  // Verify.
  EXPECT_EQ(static_cast<keymaster_key_format_t>(input->key_format),
            output->key_format);
  EXPECT_TRUE(
      VerifyKeyParameters(output->key_description, input->key_description));
  EXPECT_TRUE(VerifyVectorUint8(output->key_data, output->key_data_length,
                                input->key_data));
}

TEST(ConvertToMessage, ExportKeyRequest) {
  // Prepare.
  auto input = arc::mojom::ExportKeyRequest::New(
      arc::mojom::KeyFormat::RAW,
      std::vector<uint8_t>(kBlob1.begin(), kBlob1.end()),
      std::vector<uint8_t>(kBlob2.begin(), kBlob2.end()),
      std::vector<uint8_t>(kBlob3.begin(), kBlob3.end()));

  // Convert.
  auto output = MakeExportKeyRequest(input);

  // Verify.
  EXPECT_EQ(static_cast<keymaster_key_format_t>(input->key_format),
            output->key_format);
  ASSERT_EQ(2, output->additional_params.size());
  EXPECT_EQ(KM_TAG_APPLICATION_ID, output->additional_params[0].tag);
  EXPECT_EQ(KM_TAG_APPLICATION_DATA, output->additional_params[1].tag);
  EXPECT_TRUE(VerifyVectorUint8(output->additional_params[0].blob.data,
                                output->additional_params[0].blob.data_length,
                                input->client_id));
  EXPECT_TRUE(VerifyVectorUint8(output->additional_params[1].blob.data,
                                output->additional_params[1].blob.data_length,
                                input->app_data));
  EXPECT_TRUE(VerifyVectorUint8(output->key_blob.key_material,
                                output->key_blob.key_material_size,
                                input->key_blob));
}

TEST(ConvertToMojo, ExportKeyResult) {
  // Prepare.
  ::keymaster::ExportKeyResponse input;
  input.error = KM_ERROR_OK;
  input.SetKeyMaterial(kBlob1.data(), kBlob1.size());

  // Convert.
  auto output = MakeExportKeyResult(input);

  // Verify.
  EXPECT_EQ(output->error, input.error);
  EXPECT_TRUE(VerifyVectorUint8(input.key_data, input.key_data_length,
                                output->key_material));
}

TEST(ConvertToMojo, ExportKeyResultError) {
  // Prepare.
  ::keymaster::ExportKeyResponse input;
  input.error = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
  input.SetKeyMaterial(reinterpret_cast<void*>(0xDEADBEEF), -1337);

  // Convert.
  auto output = MakeExportKeyResult(input);

  // Verify.
  EXPECT_EQ(output->error, input.error);
  EXPECT_EQ(output->key_material.size(), 0);
}

TEST(ConvertToMessage, AttestKeyRequest) {
  // Prepare.
  auto input = arc::mojom::AttestKeyRequest::New(
      std::vector<uint8_t>(kBlob1.begin(), kBlob1.end()), KeyParameterVector());

  // Convert.
  auto output = MakeAttestKeyRequest(input);

  // Verify.
  EXPECT_TRUE(VerifyVectorUint8(output->key_blob.key_material,
                                output->key_blob.key_material_size,
                                input->key_to_attest));
  EXPECT_TRUE(VerifyKeyParameters(output->attest_params, input->attest_params));
}

TEST(ConvertToMessage, UpgradeKeyRequest) {
  // Prepare.
  auto input = arc::mojom::UpgradeKeyRequest::New(
      std::vector<uint8_t>(kBlob1.begin(), kBlob1.end()), KeyParameterVector());

  // Convert.
  auto output = MakeUpgradeKeyRequest(input);

  // Verify.
  EXPECT_TRUE(VerifyVectorUint8(output->key_blob.key_material,
                                output->key_blob.key_material_size,
                                input->key_blob_to_upgrade));
  EXPECT_TRUE(
      VerifyKeyParameters(output->upgrade_params, input->upgrade_params));
}

TEST(ConvertToMessage, BeginOperationRequest) {
  // Prepare.
  auto input = arc::mojom::BeginRequest::New(
      arc::mojom::KeyPurpose::DERIVE_KEY,
      std::vector<uint8_t>(kBlob1.begin(), kBlob1.end()), KeyParameterVector());

  // Convert.
  auto output = MakeBeginOperationRequest(input);

  // Verify.
  EXPECT_EQ(output->purpose, static_cast<keymaster_purpose_t>(input->purpose));
  EXPECT_TRUE(VerifyVectorUint8(output->key_blob.key_material,
                                output->key_blob.key_material_size,
                                input->key));
  EXPECT_TRUE(VerifyKeyParameters(output->additional_params, input->in_params));
}

TEST(ConvertToMessage, UpdateOperationRequest) {
  // Prepare.
  auto input = arc::mojom::UpdateRequest::New(
      65537, KeyParameterVector(),
      std::vector<uint8_t>(kBlob1.begin(), kBlob1.end()));

  // Convert.
  auto output = MakeUpdateOperationRequest(input);

  // Verify.
  EXPECT_EQ(output->op_handle, input->op_handle);
  EXPECT_TRUE(VerifyVectorUint8(output->input.begin(),
                                output->input.available_read(), input->input));
  EXPECT_TRUE(VerifyKeyParameters(output->additional_params, input->in_params));
}

TEST(ConvertToMessage, FinishOperationRequest) {
  // Prepare.
  auto input = arc::mojom::FinishRequest::New(
      65537, KeyParameterVector(),
      std::vector<uint8_t>(kBlob1.begin(), kBlob1.end()),
      std::vector<uint8_t>(kBlob2.begin(), kBlob2.end()));

  // Convert.
  auto output = MakeFinishOperationRequest(input);

  // Verify.
  EXPECT_EQ(output->op_handle, input->op_handle);
  EXPECT_TRUE(VerifyVectorUint8(output->signature.begin(),
                                output->signature.available_read(),
                                input->signature));
  EXPECT_TRUE(VerifyVectorUint8(output->input.begin(),
                                output->input.available_read(), input->input));
  EXPECT_TRUE(VerifyKeyParameters(output->additional_params, input->in_params));
}

}  // namespace keymaster
}  // namespace arc
