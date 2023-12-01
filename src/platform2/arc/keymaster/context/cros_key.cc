// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/context/cros_key.h"

#include <algorithm>
#include <optional>
#include <utility>

#include <base/logging.h>
#include <base/notreached.h>
#include <keymaster/authorization_set.h>
#include <keymaster/keymaster_tags.h>

#include "arc/keymaster/context/chaps_crypto_operation.h"

namespace arc {
namespace keymaster {
namespace context {

namespace {

OperationType ConvertKeymasterPurposeToOperationType(
    keymaster_purpose_t purpose) {
  switch (purpose) {
    case KM_PURPOSE_SIGN:
      return OperationType::kSign;
    case KM_PURPOSE_ENCRYPT:
    case KM_PURPOSE_DECRYPT:
    case KM_PURPOSE_VERIFY:
    case KM_PURPOSE_DERIVE_KEY:
    case KM_PURPOSE_WRAP:
      return OperationType::kUnsupported;
  }
}

Algorithm FindAlgorithm(const ::keymaster::AuthorizationSet& params) {
  keymaster_algorithm_t algorithm;

  if (!params.GetTagValue(::keymaster::TAG_ALGORITHM, &algorithm)) {
    return Algorithm::kUnsupported;
  }

  switch (algorithm) {
    case KM_ALGORITHM_RSA:
      return Algorithm::kRsa;
    case KM_ALGORITHM_AES:
    case KM_ALGORITHM_EC:
    case KM_ALGORITHM_TRIPLE_DES:
    case KM_ALGORITHM_HMAC:
      return Algorithm::kUnsupported;
  }
}

Digest FindDigest(const ::keymaster::AuthorizationSet& params) {
  keymaster_digest_t digest;

  if (!params.GetTagValue(::keymaster::TAG_DIGEST, &digest)) {
    return Digest::kNone;
  }

  switch (digest) {
    case KM_DIGEST_NONE:
      return Digest::kNone;
    case KM_DIGEST_MD5:
      return Digest::kMd5;
    case KM_DIGEST_SHA1:
      return Digest::kSha1;
    case KM_DIGEST_SHA_2_256:
      return Digest::kSha256;
    case KM_DIGEST_SHA_2_384:
      return Digest::kSha384;
    case KM_DIGEST_SHA_2_512:
      return Digest::kSha512;
    case KM_DIGEST_SHA_2_224:
      return Digest::kUnsupported;
  }
}

Padding FindPadding(const ::keymaster::AuthorizationSet& params) {
  keymaster_padding_t padding;

  if (!params.GetTagValue(::keymaster::TAG_PADDING, &padding)) {
    return Padding ::kNone;
  }

  switch (padding) {
    case KM_PAD_NONE:
      return Padding::kNone;
    case KM_PAD_PKCS7:
      return Padding::kPkcs7;
    case KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
    case KM_PAD_RSA_PKCS1_1_5_SIGN:
      return Padding::kPkcs1;
    case KM_PAD_RSA_OAEP:
    case KM_PAD_RSA_PSS:
      return Padding::kUnsupported;
  }
}

BlockMode FindBlockMode(const ::keymaster::AuthorizationSet& params) {
  keymaster_block_mode_t block_mode;

  if (!params.GetTagValue(::keymaster::TAG_BLOCK_MODE, &block_mode)) {
    return BlockMode::kNone;
  }

  switch (block_mode) {
    case KM_MODE_CBC:
      return BlockMode::kCbc;
    case KM_MODE_ECB:
    case KM_MODE_CTR:
    case KM_MODE_GCM:
      return BlockMode::kUnsupported;
  }
}

MechanismDescription CreateOperationDescription(
    const ::keymaster::Operation& operation,
    const ::keymaster::AuthorizationSet& params) {
  return MechanismDescription(
      ConvertKeymasterPurposeToOperationType(operation.purpose()),
      FindAlgorithm(params), FindDigest(params), FindPadding(params),
      FindBlockMode(params));
}

}  // anonymous namespace

CrosKeyFactory::CrosKeyFactory(base::WeakPtr<ContextAdaptor> context_adaptor,
                               keymaster_algorithm_t algorithm)
    : context_adaptor_(context_adaptor),
      sign_factory_(
          std::make_unique<CrosOperationFactory>(algorithm, KM_PURPOSE_SIGN)) {}

keymaster_error_t CrosKeyFactory::LoadKey(
    KeyData&& key_data,
    ::keymaster::AuthorizationSet&& hw_enforced,
    ::keymaster::AuthorizationSet&& sw_enforced,
    ::keymaster::UniquePtr<::keymaster::Key>* key) const {
  switch (key_data.data_case()) {
    case KeyData::DataCase::kChapsKey:
      key->reset(new ChapsKey(std::move(hw_enforced), std::move(sw_enforced),
                              this, std::move(key_data)));
      return KM_ERROR_OK;
    case KeyData::kArcKey:
      NOTREACHED() << "CrosKeyFactory cannot load ARC keys.";
      return KM_ERROR_UNIMPLEMENTED;
    case KeyData::DATA_NOT_SET:
      LOG(ERROR) << "Tried to load CrOS key but KeyData is not set.";
      return KM_ERROR_UNKNOWN_ERROR;
  }
}

keymaster_error_t CrosKeyFactory::LoadKey(
    ::keymaster::KeymasterKeyBlob&& key_material,
    const ::keymaster::AuthorizationSet& additional_params,
    ::keymaster::AuthorizationSet&& hw_enforced,
    ::keymaster::AuthorizationSet&& sw_enforced,
    ::keymaster::UniquePtr<::keymaster::Key>* key) const {
  NOTREACHED() << __func__ << " should never be called";
  return KM_ERROR_UNIMPLEMENTED;
}

::keymaster::OperationFactory* CrosKeyFactory::GetOperationFactory(
    keymaster_purpose_t purpose) const {
  switch (purpose) {
    case KM_PURPOSE_SIGN:
      return sign_factory_.get();
    case KM_PURPOSE_ENCRYPT:
    case KM_PURPOSE_DECRYPT:
    case KM_PURPOSE_VERIFY:
    case KM_PURPOSE_DERIVE_KEY:
    case KM_PURPOSE_WRAP:
      LOG(WARNING) << "No factory for purpose=" << purpose;
      return nullptr;
  }
}

keymaster_error_t CrosKeyFactory::GenerateKey(
    const ::keymaster::AuthorizationSet& key_description,
    ::keymaster::KeymasterKeyBlob* key_blob,
    ::keymaster::AuthorizationSet* hw_enforced,
    ::keymaster::AuthorizationSet* sw_enforced) const {
  NOTREACHED() << __func__ << " should never be called";
  return KM_ERROR_UNIMPLEMENTED;
}

keymaster_error_t CrosKeyFactory::ImportKey(
    const ::keymaster::AuthorizationSet& key_description,
    keymaster_key_format_t input_key_material_format,
    const ::keymaster::KeymasterKeyBlob& input_key_material,
    ::keymaster::KeymasterKeyBlob* output_key_blob,
    ::keymaster::AuthorizationSet* hw_enforced,
    ::keymaster::AuthorizationSet* sw_enforced) const {
  NOTREACHED() << __func__ << " should never be called";
  return KM_ERROR_UNIMPLEMENTED;
}

const keymaster_key_format_t* CrosKeyFactory::SupportedImportFormats(
    size_t* format_count) const {
  NOTREACHED() << __func__ << " should never be called";
  *format_count = 0;
  return nullptr;
}

const keymaster_key_format_t* CrosKeyFactory::SupportedExportFormats(
    size_t* format_count) const {
  NOTREACHED() << __func__ << " should never be called";
  *format_count = 0;
  return nullptr;
}

CrosKey::CrosKey(::keymaster::AuthorizationSet&& hw_enforced,
                 ::keymaster::AuthorizationSet&& sw_enforced,
                 const CrosKeyFactory* key_factory,
                 KeyData&& key_data)
    : ::keymaster::Key(
          std::move(hw_enforced), std::move(sw_enforced), key_factory),
      key_data_(std::move(key_data)) {}

CrosKey::~CrosKey() = default;

ChapsKey::ChapsKey(::keymaster::AuthorizationSet&& hw_enforced,
                   ::keymaster::AuthorizationSet&& sw_enforced,
                   const CrosKeyFactory* key_factory,
                   KeyData&& key_data)
    : CrosKey(std::move(hw_enforced),
              std::move(sw_enforced),
              key_factory,
              std::move(key_data)) {}

ChapsKey::ChapsKey(ChapsKey&& chaps_key)
    : ChapsKey(chaps_key.hw_enforced_move(),
               chaps_key.sw_enforced_move(),
               chaps_key.cros_key_factory(),
               std::move(chaps_key.key_data_)) {}

ChapsKey::~ChapsKey() = default;

ChapsKey& ChapsKey::operator=(ChapsKey&& other) {
  hw_enforced_ = other.hw_enforced_move();
  sw_enforced_ = other.sw_enforced_move();
  key_factory_ = other.cros_key_factory();
  key_data_ = std::move(other.key_data_);
  return *this;
}

keymaster_error_t ChapsKey::formatted_key_material(
    keymaster_key_format_t format,
    ::keymaster::UniquePtr<uint8_t[]>* out_material,
    size_t* out_size) const {
  // KM_KEY_FORMAT_X509 refers to the SubjectPublicKeyInfo, and that's the only
  // format we support.
  if (format != KM_KEY_FORMAT_X509)
    return KM_ERROR_UNSUPPORTED_KEY_FORMAT;

  if (out_material == nullptr || out_size == nullptr)
    return KM_ERROR_OUTPUT_PARAMETER_NULL;

  ChapsClient chaps_client(cros_key_factory()->context_adaptor(), slot());
  std::optional<brillo::Blob> spki =
      chaps_client.ExportSubjectPublicKeyInfo(label(), id());
  if (!spki.has_value())
    return KM_ERROR_UNKNOWN_ERROR;

  out_material->reset(new uint8_t[spki->size()]);
  std::copy(spki->begin(), spki->end(), out_material->get());
  *out_size = spki->size();
  return KM_ERROR_OK;
}

CrosOperationFactory::CrosOperationFactory(keymaster_algorithm_t algorithm,
                                           keymaster_purpose_t purpose)
    : algorithm_(algorithm), purpose_(purpose) {}

CrosOperationFactory::~CrosOperationFactory() = default;

::keymaster::OperationFactory::KeyType CrosOperationFactory::registry_key()
    const {
  return ::keymaster::OperationFactory::KeyType(algorithm_, purpose_);
}

::keymaster::OperationPtr CrosOperationFactory::CreateOperation(
    ::keymaster::Key&& key,
    const ::keymaster::AuthorizationSet& begin_params,
    keymaster_error_t* error) {
  ChapsKey* chaps_key = dynamic_cast<ChapsKey*>(&key);

  if (!chaps_key) {
    NOTREACHED() << __func__ << " should not be called with non CrOS key.";
    *error = KM_ERROR_UNKNOWN_ERROR;
    return nullptr;
  }

  ::keymaster::UniquePtr<::keymaster::Operation> operation(
      new CrosOperation(purpose_, std::move(*chaps_key)));
  *error = KM_ERROR_OK;
  return operation;
}

CrosOperation::CrosOperation(keymaster_purpose_t purpose, ChapsKey&& key)
    : ::keymaster::Operation(
          purpose, key.hw_enforced_move(), key.sw_enforced_move()),
      operation_(std::make_unique<ChapsCryptoOperation>(
          key.cros_key_factory()->context_adaptor(),
          key.slot(),
          key.label(),
          key.id())) {}

CrosOperation::~CrosOperation() = default;

keymaster_error_t CrosOperation::Begin(
    const ::keymaster::AuthorizationSet& input_params,
    ::keymaster::AuthorizationSet* /* output_params */) {
  MechanismDescription d = CreateOperationDescription(*this, input_params);

  std::optional<uint64_t> handle = operation_->Begin(d);

  if (!handle.has_value())
    return KM_ERROR_UNKNOWN_ERROR;

  operation_handle_ = handle.value();
  return KM_ERROR_OK;
}

keymaster_error_t CrosOperation::Update(
    const ::keymaster::AuthorizationSet& /* input_params */,
    const ::keymaster::Buffer& input,
    ::keymaster::AuthorizationSet* /* output_params */,
    ::keymaster::Buffer* /* output */,
    size_t* input_consumed) {
  brillo::Blob input_blob(input.begin(), input.end());
  std::optional<brillo::Blob> output = operation_->Update(input_blob);

  if (!output.has_value()) {
    *input_consumed = 0;
    return KM_ERROR_UNKNOWN_ERROR;
  }

  *input_consumed = input_blob.size();
  return KM_ERROR_OK;
}

keymaster_error_t CrosOperation::Finish(
    const ::keymaster::AuthorizationSet& /* input_params */,
    const ::keymaster::Buffer& input,
    const ::keymaster::Buffer& /* signature */,
    ::keymaster::AuthorizationSet* /* output_params */,
    ::keymaster::Buffer* output) {
  // Run an update with the last piece of input, if any.
  if (input.available_read() > 0) {
    brillo::Blob input_blob(input.begin(), input.end());
    std::optional<brillo::Blob> updateResult = operation_->Update(input_blob);

    if (!updateResult.has_value())
      return KM_ERROR_UNKNOWN_ERROR;
  }

  std::optional<brillo::Blob> finish_result = operation_->Finish();
  if (!finish_result.has_value())
    return KM_ERROR_UNKNOWN_ERROR;

  output->Reinitialize(finish_result->size());
  output->write(finish_result->data(), finish_result->size());
  return KM_ERROR_OK;
}

keymaster_error_t CrosOperation::Abort() {
  return operation_->Abort() ? KM_ERROR_OK : KM_ERROR_UNKNOWN_ERROR;
}

}  // namespace context
}  // namespace keymaster
}  // namespace arc
