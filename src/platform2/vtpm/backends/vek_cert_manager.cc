// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/vek_cert_manager.h"

#include <string>
#include <vector>

#include <base/check.h>
#include <trunks/tpm_constants.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

namespace {

constexpr trunks::TPMI_ALG_HASH kNameAlgorithm = trunks::TPM_ALG_SHA256;
constexpr trunks::TPMA_NV kAttributes =
    trunks::TPMA_NV_PPWRITE | trunks::TPMA_NV_WRITEDEFINE |
    trunks::TPMA_NV_PLATFORMCREATE | trunks::TPMA_NV_AUTHREAD |
    trunks::TPMA_NV_NO_DA;

}  // namespace

VekCertManager::VekCertManager(trunks::TPM_NV_INDEX index, Blob* blob)
    : nv_index_(index), blob_(blob) {
  CHECK(blob_);
}

trunks::TPM_RC VekCertManager::Read(trunks::TPM_NV_INDEX nv_index,
                                    const std::string& password,
                                    std::string& nv_data) {
  if (nv_index != nv_index_) {
    return trunks::TPM_RC_NV_SPACE;
  }
  // Only accepts empty auth.
  if (!password.empty()) {
    return trunks::TPM_RC_BAD_AUTH;
  }
  return blob_->Get(nv_data);
}

trunks::TPM_RC VekCertManager::GetDataSize(trunks::TPM_NV_INDEX nv_index,
                                           trunks::UINT16& data_size) {
  std::string nv_data;
  if (nv_index != nv_index_) {
    return trunks::TPM_RC_NV_SPACE;
  }
  trunks::TPM_RC rc = blob_->Get(nv_data);
  if (rc) {
    return rc;
  }
  data_size = nv_data.size();
  return trunks::TPM_RC_SUCCESS;
}

trunks::TPM_RC VekCertManager::GetAttributes(trunks::TPM_NV_INDEX nv_index,
                                             trunks::TPMA_NV& attributes) {
  if (nv_index != nv_index_) {
    return trunks::TPM_RC_NV_SPACE;
  }
  attributes = kAttributes;
  return trunks::TPM_RC_SUCCESS;
}

trunks::TPM_RC VekCertManager::GetNameAlgorithm(
    trunks::TPM_NV_INDEX nv_index, trunks::TPMI_ALG_HASH& algorithm) {
  if (nv_index != nv_index_) {
    return trunks::TPM_RC_NV_SPACE;
  }
  algorithm = kNameAlgorithm;
  return trunks::TPM_RC_SUCCESS;
}

trunks::TPM_RC VekCertManager::ListHandles(
    std::vector<trunks::TPM_HANDLE>& handles) {
  handles.push_back(nv_index_);
  return trunks::TPM_RC_SUCCESS;
}

}  // namespace vtpm
