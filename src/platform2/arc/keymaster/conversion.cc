// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/conversion.h"

#include <utility>

namespace arc {
namespace keymaster {

namespace {

keymaster_key_format_t ConvertEnum(arc::mojom::KeyFormat key_format) {
  return static_cast<keymaster_key_format_t>(key_format);
}

keymaster_purpose_t ConvertEnum(arc::mojom::KeyPurpose key_purpose) {
  return static_cast<keymaster_purpose_t>(key_purpose);
}

keymaster_tag_t ConvertEnum(uint32_t tag) {
  return static_cast<keymaster_tag_t>(tag);
}

class KmParamSet {
 public:
  explicit KmParamSet(const std::vector<arc::mojom::KeyParameterPtr>& data) {
    param_set_.params = new keymaster_key_param_t[data.size()];
    param_set_.length = data.size();
    for (size_t i = 0; i < data.size(); ++i) {
      keymaster_tag_t tag = ConvertEnum(data[i]->tag);
      switch (keymaster_tag_get_type(tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
          if (data[i]->param->is_integer()) {
            param_set_.params[i] =
                keymaster_param_enum(tag, data[i]->param->get_integer());
          } else {
            param_set_.params[i].tag = KM_TAG_INVALID;
          }
          break;
        case KM_UINT:
        case KM_UINT_REP:
          if (data[i]->param->is_integer()) {
            param_set_.params[i] =
                keymaster_param_int(tag, data[i]->param->get_integer());
          } else {
            param_set_.params[i].tag = KM_TAG_INVALID;
          }
          break;
        case KM_ULONG:
        case KM_ULONG_REP:
          if (data[i]->param->is_long_integer()) {
            param_set_.params[i] =
                keymaster_param_long(tag, data[i]->param->get_long_integer());
          } else {
            param_set_.params[i].tag = KM_TAG_INVALID;
          }
          break;
        case KM_DATE:
          if (data[i]->param->is_date_time()) {
            param_set_.params[i] =
                keymaster_param_date(tag, data[i]->param->get_date_time());
          } else {
            param_set_.params[i].tag = KM_TAG_INVALID;
          }
          break;
        case KM_BOOL:
          if (data[i]->param->is_boolean_value() &&
              data[i]->param->get_boolean_value()) {
            param_set_.params[i] = keymaster_param_bool(tag);
          } else {
            param_set_.params[i].tag = KM_TAG_INVALID;
          }
          break;
        case KM_BIGNUM:
        case KM_BYTES:
          if (data[i]->param->is_blob()) {
            param_set_.params[i] =
                keymaster_param_blob(tag, data[i]->param->get_blob().data(),
                                     data[i]->param->get_blob().size());
          } else {
            param_set_.params[i].tag = KM_TAG_INVALID;
          }
          break;
        case KM_INVALID:
        default:
          param_set_.params[i].tag = KM_TAG_INVALID;
          /* just skip */
          break;
      }
    }
  }

  KmParamSet(KmParamSet&& other)
      : param_set_{other.param_set_.params, other.param_set_.length} {
    other.param_set_.length = 0;
    other.param_set_.params = nullptr;
  }
  KmParamSet(const KmParamSet&) = delete;
  KmParamSet& operator=(const KmParamSet&) = delete;

  ~KmParamSet() { delete[] param_set_.params; }

  inline const keymaster_key_param_set_t& param_set() const {
    return param_set_;
  }

 private:
  keymaster_key_param_set_t param_set_;
};

}  // namespace

std::unique_ptr<::keymaster::GetKeyCharacteristicsRequest>
MakeGetKeyCharacteristicsRequest(
    const ::arc::mojom::GetKeyCharacteristicsRequestPtr& value) {
  auto out = std::make_unique<::keymaster::GetKeyCharacteristicsRequest>();
  out->SetKeyMaterial(value->key_blob.data(), value->key_blob.size());
  ConvertToMessage(value->client_id, value->app_data, &out->additional_params);
  return out;
}

std::unique_ptr<::keymaster::GenerateKeyRequest> MakeGenerateKeyRequest(
    const std::vector<arc::mojom::KeyParameterPtr>& data) {
  auto out = std::make_unique<::keymaster::GenerateKeyRequest>();
  ConvertToMessage(data, &out->key_description);
  return out;
}

std::unique_ptr<::keymaster::ImportKeyRequest> MakeImportKeyRequest(
    const arc::mojom::ImportKeyRequestPtr& request) {
  auto out = std::make_unique<::keymaster::ImportKeyRequest>();
  ConvertToMessage(request->key_description, &out->key_description);

  out->key_format = ConvertEnum(request->key_format);
  out->SetKeyMaterial(request->key_data.data(), request->key_data.size());
  return out;
}

std::unique_ptr<::keymaster::ExportKeyRequest> MakeExportKeyRequest(
    const arc::mojom::ExportKeyRequestPtr& request) {
  auto out = std::make_unique<::keymaster::ExportKeyRequest>();
  out->key_format = ConvertEnum(request->key_format);
  ConvertToMessage(request->client_id, request->app_data,
                   &out->additional_params);
  out->SetKeyMaterial(request->key_blob.data(), request->key_blob.size());
  return out;
}

std::unique_ptr<::keymaster::AttestKeyRequest> MakeAttestKeyRequest(
    const arc::mojom::AttestKeyRequestPtr& request) {
  auto out = std::make_unique<::keymaster::AttestKeyRequest>();
  ConvertToMessage(request->attest_params, &out->attest_params);
  out->SetKeyMaterial(request->key_to_attest.data(),
                      request->key_to_attest.size());
  return out;
}

std::unique_ptr<::keymaster::UpgradeKeyRequest> MakeUpgradeKeyRequest(
    const arc::mojom::UpgradeKeyRequestPtr& request) {
  auto out = std::make_unique<::keymaster::UpgradeKeyRequest>();
  ConvertToMessage(request->upgrade_params, &out->upgrade_params);
  out->SetKeyMaterial(request->key_blob_to_upgrade.data(),
                      request->key_blob_to_upgrade.size());
  return out;
}

std::unique_ptr<::keymaster::BeginOperationRequest> MakeBeginOperationRequest(
    const arc::mojom::BeginRequestPtr& request) {
  auto out = std::make_unique<::keymaster::BeginOperationRequest>();
  out->purpose = ConvertEnum(request->purpose);
  out->SetKeyMaterial(request->key.data(), request->key.size());
  ConvertToMessage(request->in_params, &out->additional_params);
  return out;
}

std::unique_ptr<::keymaster::UpdateOperationRequest> MakeUpdateOperationRequest(
    const arc::mojom::UpdateRequestPtr& request) {
  auto out = std::make_unique<::keymaster::UpdateOperationRequest>();
  out->op_handle = request->op_handle;
  ConvertToMessage(request->input, &out->input);
  ConvertToMessage(request->in_params, &out->additional_params);
  return out;
}

std::unique_ptr<::keymaster::FinishOperationRequest> MakeFinishOperationRequest(
    const arc::mojom::FinishRequestPtr& request) {
  auto out = std::make_unique<::keymaster::FinishOperationRequest>();
  out->op_handle = request->op_handle;
  ConvertToMessage(request->input, &out->input);
  ConvertToMessage(request->signature, &out->signature);
  ConvertToMessage(request->in_params, &out->additional_params);
  return out;
}

arc::mojom::GetKeyCharacteristicsResultPtr MakeGetKeyCharacteristicsResult(
    const ::keymaster::GetKeyCharacteristicsResponse& km_response) {
  if (km_response.error == KM_ERROR_OK) {
    return arc::mojom::GetKeyCharacteristicsResult::New(
        arc::mojom::KeyCharacteristics::New(
            ConvertToMojo(km_response.unenforced),
            ConvertToMojo(km_response.enforced)),
        km_response.error);
  }

  return arc::mojom::GetKeyCharacteristicsResult::New(
      arc::mojom::KeyCharacteristics::New(), km_response.error);
}

arc::mojom::GenerateKeyResultPtr MakeGenerateKeyResult(
    const ::keymaster::GenerateKeyResponse& km_response) {
  if (km_response.error == KM_ERROR_OK) {
    return arc::mojom::GenerateKeyResult::New(
        ConvertToMojo(km_response.key_blob.key_material,
                      km_response.key_blob.key_material_size),
        arc::mojom::KeyCharacteristics::New(
            ConvertToMojo(km_response.unenforced),
            ConvertToMojo(km_response.enforced)),
        km_response.error);
  }

  return arc::mojom::GenerateKeyResult::New(
      std::vector<uint8_t>(), arc::mojom::KeyCharacteristics::New(),
      km_response.error);
}

arc::mojom::ImportKeyResultPtr MakeImportKeyResult(
    const ::keymaster::ImportKeyResponse& km_response) {
  if (km_response.error == KM_ERROR_OK) {
    return arc::mojom::ImportKeyResult::New(
        ConvertToMojo(km_response.key_blob.key_material,
                      km_response.key_blob.key_material_size),
        arc::mojom::KeyCharacteristics::New(
            ConvertToMojo(km_response.unenforced),
            ConvertToMojo(km_response.enforced)),
        km_response.error);
  }

  return arc::mojom::ImportKeyResult::New(std::vector<uint8_t>(),
                                          arc::mojom::KeyCharacteristics::New(),
                                          km_response.error);
}

arc::mojom::ExportKeyResultPtr MakeExportKeyResult(
    const ::keymaster::ExportKeyResponse& km_response) {
  if (km_response.error == KM_ERROR_OK) {
    return arc::mojom::ExportKeyResult::New(
        ConvertToMojo(km_response.key_data, km_response.key_data_length),
        km_response.error);
  }

  return arc::mojom::ExportKeyResult::New(std::vector<uint8_t>(),
                                          km_response.error);
}

arc::mojom::AttestKeyResultPtr MakeAttestKeyResult(
    const ::keymaster::AttestKeyResponse& km_response) {
  if (km_response.error == KM_ERROR_OK) {
    return arc::mojom::AttestKeyResult::New(
        ConvertToMojo(km_response.certificate_chain), km_response.error);
  }

  return arc::mojom::AttestKeyResult::New(std::vector<std::vector<uint8_t>>(),
                                          km_response.error);
}

arc::mojom::UpgradeKeyResultPtr MakeUpgradeKeyResult(
    const ::keymaster::UpgradeKeyResponse& km_response) {
  if (km_response.error == KM_ERROR_OK) {
    return arc::mojom::UpgradeKeyResult::New(
        ConvertToMojo(km_response.upgraded_key.key_material,
                      km_response.upgraded_key.key_material_size),
        km_response.error);
  }

  return arc::mojom::UpgradeKeyResult::New(std::vector<uint8_t>(),
                                           km_response.error);
}

arc::mojom::BeginResultPtr MakeBeginResult(
    const ::keymaster::BeginOperationResponse& km_response) {
  if (km_response.error == KM_ERROR_OK) {
    return arc::mojom::BeginResult::New(
        ConvertToMojo(km_response.output_params), km_response.op_handle,
        km_response.error);
  }

  return arc::mojom::BeginResult::New(
      std::vector<arc::mojom::KeyParameterPtr>(), km_response.op_handle,
      km_response.error);
}

arc::mojom::UpdateResultPtr MakeUpdateResult(
    const ::keymaster::UpdateOperationResponse& km_response) {
  if (km_response.error == KM_ERROR_OK) {
    return arc::mojom::UpdateResult::New(
        km_response.input_consumed, ConvertToMojo(km_response.output_params),
        ConvertToMojo(km_response.output.begin(),
                      km_response.output.available_read()),
        km_response.error);
  }

  return arc::mojom::UpdateResult::New(
      0, std::vector<arc::mojom::KeyParameterPtr>(), std::vector<uint8_t>(),
      km_response.error);
}

arc::mojom::FinishResultPtr MakeFinishResult(
    const ::keymaster::FinishOperationResponse& km_response) {
  if (km_response.error == KM_ERROR_OK) {
    return arc::mojom::FinishResult::New(
        ConvertToMojo(km_response.output_params),
        ConvertToMojo(km_response.output.begin(),
                      km_response.output.available_read()),
        km_response.error);
  }

  return arc::mojom::FinishResult::New(
      std::vector<arc::mojom::KeyParameterPtr>(), std::vector<uint8_t>(),
      km_response.error);
}

std::vector<uint8_t> ConvertToMojo(const uint8_t* data, const size_t size) {
  return std::vector<uint8_t>(data, data + size);
}

std::vector<std::vector<uint8_t>> ConvertToMojo(
    const keymaster_cert_chain_t& cert) {
  std::vector<std::vector<uint8_t>> out(cert.entry_count);
  for (size_t i = 0; i < cert.entry_count; ++i) {
    const auto& entry = cert.entries[i];
    out[i] = ConvertToMojo(entry.data, entry.data_length);
  }
  return out;
}

std::vector<arc::mojom::KeyParameterPtr> ConvertToMojo(
    const keymaster_key_param_set_t& param_set) {
  if (param_set.length == 0 || !param_set.params)
    return std::vector<arc::mojom::KeyParameterPtr>();

  std::vector<arc::mojom::KeyParameterPtr> out(param_set.length);
  keymaster_key_param_t* params = param_set.params;
  for (size_t i = 0; i < param_set.length; ++i) {
    keymaster_tag_t tag = params[i].tag;
    arc::mojom::IntegerKeyParamPtr param;
    switch (keymaster_tag_get_type(tag)) {
      case KM_ENUM:
      case KM_ENUM_REP:
        param = arc::mojom::IntegerKeyParam::NewInteger(params[i].enumerated);
        break;
      case KM_UINT:
      case KM_UINT_REP:
        param = arc::mojom::IntegerKeyParam::NewInteger(params[i].integer);
        break;
      case KM_ULONG:
      case KM_ULONG_REP:
        param =
            arc::mojom::IntegerKeyParam::NewLongInteger(params[i].long_integer);
        break;
      case KM_DATE:
        param = arc::mojom::IntegerKeyParam::NewDateTime(params[i].date_time);
        break;
      case KM_BOOL:
        param = arc::mojom::IntegerKeyParam::NewBooleanValue(params[i].boolean);
        break;
      case KM_BIGNUM:
      case KM_BYTES:
        param = arc::mojom::IntegerKeyParam::NewBlob(
            ConvertToMojo(params[i].blob.data, params[i].blob.data_length));
        break;
      case KM_INVALID:
        tag = KM_TAG_INVALID;
        /* just skip */
        break;
    }

    out[i] = arc::mojom::KeyParameter::New(tag, std::move(param));
  }

  return out;
}

void ConvertToMessage(const std::vector<uint8_t>& data,
                      ::keymaster::Buffer* out) {
  out->Reinitialize(data.data(), data.size());
}

void ConvertToMessage(const std::vector<uint8_t>& clientId,
                      const std::vector<uint8_t>& appData,
                      ::keymaster::AuthorizationSet* params) {
  params->Clear();
  if (!clientId.empty()) {
    params->push_back(::keymaster::TAG_APPLICATION_ID, clientId.data(),
                      clientId.size());
  }
  if (!appData.empty()) {
    params->push_back(::keymaster::TAG_APPLICATION_DATA, appData.data(),
                      appData.size());
  }
}

void ConvertToMessage(const std::vector<arc::mojom::KeyParameterPtr>& data,
                      ::keymaster::AuthorizationSet* out) {
  KmParamSet param_set(data);
  out->Reinitialize(param_set.param_set());
}

}  // namespace keymaster
}  // namespace arc
