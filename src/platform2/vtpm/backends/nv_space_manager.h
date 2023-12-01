// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_NV_SPACE_MANAGER_H_
#define VTPM_BACKENDS_NV_SPACE_MANAGER_H_

#include <string>
#include <vector>

#include <trunks/tpm_generated.h>

namespace vtpm {

// `NvSpaceManager` manages the authorization, attributes, and data of one or
// more NV spaces.
class NvSpaceManager {
 public:
  virtual ~NvSpaceManager() = default;

  // Verifies the password for `nv_index`, and set `data` if the password
  // matches. The password authorization is by design directly defined by
  // implementation.
  virtual trunks::TPM_RC Read(trunks::TPM_NV_INDEX nv_index,
                              const std::string& password,
                              std::string& nv_data) = 0;

  // Sets the data size of `nv_index` to `data_size` and returns
  // `TPM_RC_SUCCESS` in a successful case. Otherwise, returns a certain error
  // code.
  virtual trunks::TPM_RC GetDataSize(trunks::TPM_NV_INDEX nv_index,
                                     trunks::UINT16& data_size) = 0;

  // Sets the data size of `nv_index` to `attributes` and returns
  // `TPM_RC_SUCCESS` in a successful case. Otherwise, returns a certain error
  // code.
  virtual trunks::TPM_RC GetAttributes(trunks::TPM_NV_INDEX nv_index,
                                       trunks::TPMA_NV& attributes) = 0;

  // Sets the name algorithm of `nv_index` to `algorithm` and returns
  // `TPM_RC_SUCCESS` in a successful case. Otherwise, returns a certain error
  // code.
  virtual trunks::TPM_RC GetNameAlgorithm(trunks::TPM_NV_INDEX nv_index,
                                          trunks::TPMI_ALG_HASH& algorithm) = 0;

  // List the managed TPM NV index handles.
  virtual trunks::TPM_RC ListHandles(
      std::vector<trunks::TPM_HANDLE>& handles) = 0;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_NV_SPACE_MANAGER_H_
