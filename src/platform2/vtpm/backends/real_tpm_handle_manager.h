// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_REAL_TPM_HANDLE_MANAGER_H_
#define VTPM_BACKENDS_REAL_TPM_HANDLE_MANAGER_H_

#include "vtpm/backends/tpm_handle_manager.h"

#include <map>
#include <unordered_map>
#include <vector>

#include <trunks/tpm_generated.h>
#include <trunks/trunks_factory.h>

#include "vtpm/backends/blob.h"
#include "vtpm/backends/nv_space_manager.h"

namespace vtpm {

// A real implementation of `TpmHandleManager` that manages the usage meaning of
// virtual TPM handles and their association with states on the host TPM.
class RealTpmHandleManager : public TpmHandleManager {
 public:
  // Constructs an instance. `blob_` is set to table`.
  RealTpmHandleManager(trunks::TrunksFactory* trunks_factory,
                       NvSpaceManager* nv_space_manager,
                       std::map<trunks::TPM_HANDLE, Blob*> table);
  ~RealTpmHandleManager() override = default;

  // Checks if `handles falls in the range of what this class supports.
  // Currently only "persistent handle type" is supported.
  bool IsHandleTypeSuppoerted(trunks::TPM_HANDLE handle) override;

  // Gets the list of virtual handles that are:
  // 1. recognised by this instance, and
  // 2. of the same types of `starting_handle`, as the interface defines, and,
  // 3. no smaller than `starting_handle` in value, as the interface defines.
  // The result is stored in `found_handles`.
  trunks::TPM_RC GetHandleList(
      trunks::TPM_HANDLE starting_handle,
      std::vector<trunks::TPM_HANDLE>* found_handles) override;

  trunks::TPM_RC TranslateHandle(trunks::TPM_HANDLE handle,
                                 ScopedHostKeyHandle* host_handle) override;

  trunks::TPM_RC FlushHostHandle(trunks::TPM_HANDLE handle) override;

  void OnLoad(trunks::TPM_HANDLE parent, trunks::TPM_HANDLE child) override;

  void OnUnload(trunks::TPM_HANDLE handle) override;

 private:
  trunks::TrunksFactory* const trunks_factory_;

  NvSpaceManager* const nv_space_manager_;

  // Stores virtual handles and their getter of corresponding data on/from the
  // host TPM.
  std::map<trunks::TPM_HANDLE, Blob*> handle_mapping_table_;

  std::map<trunks::TPM_HANDLE, std::vector<trunks::TPM_HANDLE>>
      child_parent_table_;
  std::unordered_map<trunks::TPM_HANDLE, int> child_count_table_;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_REAL_TPM_HANDLE_MANAGER_H_
