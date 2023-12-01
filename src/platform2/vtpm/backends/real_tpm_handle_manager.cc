// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/real_tpm_handle_manager.h"

#include <memory>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <trunks/tpm_generated.h>
#include <trunks/trunks_factory.h>

#include "vtpm/backends/scoped_host_key_handle.h"

namespace vtpm {

namespace {

bool IsTransient(trunks::TPM_HANDLE handle) {
  return (handle & trunks::HR_RANGE_MASK) == (trunks::HR_TRANSIENT);
}

bool IsPersistent(trunks::TPM_HANDLE handle) {
  return (handle & trunks::HR_RANGE_MASK) == (trunks::HR_PERSISTENT);
}

bool IsPermanent(trunks::TPM_HANDLE handle) {
  return (handle & trunks::HR_RANGE_MASK) == (trunks::HR_PERMANENT);
}

bool IsPolicy(trunks::TPM_HANDLE handle) {
  return (handle & trunks::HR_RANGE_MASK) == (trunks::HR_POLICY_SESSION);
}

bool IsNvram(trunks::TPM_HANDLE handle) {
  return (handle & trunks::HR_RANGE_MASK) == (trunks::HR_NV_INDEX);
}

}  // namespace

RealTpmHandleManager::RealTpmHandleManager(
    trunks::TrunksFactory* trunks_factory,
    NvSpaceManager* nv_space_manager,
    std::map<trunks::TPM_HANDLE, Blob*> table)
    : trunks_factory_(trunks_factory),
      nv_space_manager_(nv_space_manager),
      handle_mapping_table_(table) {
  CHECK(trunks_factory_);
  for (const auto& entry : handle_mapping_table_) {
    DCHECK(IsPersistent(entry.first))
        << "Handle with Unsupported handle type: " << entry.first;
  }
}

bool RealTpmHandleManager::IsHandleTypeSuppoerted(trunks::TPM_HANDLE handle) {
  return IsTransient(handle) || IsPersistent(handle) || IsPermanent(handle) ||
         IsPolicy(handle) || IsNvram(handle);
}

trunks::TPM_RC RealTpmHandleManager::GetHandleList(
    trunks::TPM_HANDLE starting_handle,
    std::vector<trunks::TPM_HANDLE>* found_handles) {
  if (IsPersistent(starting_handle)) {
    for (auto iter = handle_mapping_table_.lower_bound(starting_handle);
         iter != handle_mapping_table_.end(); ++iter) {
      Blob* blob = iter->second;
      std::string blob_not_used;
      const trunks::TPM_RC rc = blob->Get(blob_not_used);
      if (rc) {
        found_handles->clear();
        return rc;
      }
      // Note that the handle type is not validated because we support only 1
      // type for now, and invalid entries are guarded in the constructor. But
      // it wont stand when we have multiple supported types that are maintained
      // in `handle_mapping_table_`.
      found_handles->push_back(iter->first);
    }
  } else if (IsTransient(starting_handle)) {
    for (auto iter = child_parent_table_.lower_bound(starting_handle);
         iter != child_parent_table_.end(); ++iter) {
      found_handles->push_back(iter->first);
    }
  } else if (IsNvram(starting_handle)) {
    nv_space_manager_->ListHandles(*found_handles);
  } else {
    return trunks::TPM_RC_HANDLE;
  }
  return trunks::TPM_RC_SUCCESS;
}

trunks::TPM_RC RealTpmHandleManager::TranslateHandle(
    trunks::TPM_HANDLE handle, ScopedHostKeyHandle* host_handle) {
  if (!IsHandleTypeSuppoerted(handle)) {
    return trunks::TPM_RC_HANDLE;
  }

  // TODO(b/230343588): Limit the access to the policy sessions not created by
  // the guest.
  // Unlike key handles, the risk of exposing the host policy session handle is
  // lower, though ideally we should treat it like a session handle.
  // We will need to refine the interface of `Onload()`, and consider better
  // structure of the implementation.
  if (IsPolicy(handle) || IsPermanent(handle)) {
    *host_handle = ScopedHostKeyHandle(this, handle);
    return trunks::TPM_RC_SUCCESS;
  }

  if (IsTransient(handle)) {
    // If the is transient, it must be in `child_parent_table_` because it must
    // be derived from the virtual root keys.
    if (child_parent_table_.count(handle) > 0) {
      // Copy the value as it is, for we don't do virtualization of a transient
      // handle.
      *host_handle = ScopedHostKeyHandle(this, handle);
      return trunks::TPM_RC_SUCCESS;
    }
    return trunks::TPM_RC_HANDLE;
  }

  DCHECK(IsPersistent(handle));

  auto iter = handle_mapping_table_.find(handle);
  if (iter == handle_mapping_table_.end()) {
    return trunks::TPM_RC_HANDLE;
  }
  // Load the corresponding transient host key.
  std::string host_key_blob;
  trunks::TPM_RC rc = iter->second->Get(host_key_blob);
  if (rc) {
    return rc;
  }
  // Load the key to host TPM.
  // Always use the correct auth. If the guest feeds wrong auth, the follow-up
  // operation will fail anyway.
  std::unique_ptr<trunks::AuthorizationDelegate> empty_password_authorization =
      trunks_factory_->GetPasswordAuthorization(std::string());
  trunks::TPM_HANDLE raw_host_handle;
  rc = trunks_factory_->GetTpmUtility()->LoadKey(
      host_key_blob, empty_password_authorization.get(), &raw_host_handle);
  if (rc) {
    return rc;
  }

  // Construct the ScopedHostKeyHandle.
  *host_handle = ScopedHostKeyHandle(this, raw_host_handle, raw_host_handle);
  return trunks::TPM_RC_SUCCESS;
}

trunks::TPM_RC RealTpmHandleManager::FlushHostHandle(
    trunks::TPM_HANDLE handle) {
  // Should not flush the handle if other loaded handles are derived from it.
  if (child_count_table_.count(handle) > 0) {
    return trunks::TPM_RC_SUCCESS;
  }
  return trunks_factory_->GetTpm()->FlushContextSync(
      handle, /*authorization_delegate=*/nullptr);
}

void RealTpmHandleManager::OnLoad(trunks::TPM_HANDLE parent,
                                  trunks::TPM_HANDLE child) {
  child_parent_table_[child].push_back(parent);
  ++child_count_table_[parent];
}

void RealTpmHandleManager::OnUnload(trunks::TPM_HANDLE handle) {
  // The performance is suboptimal due to repeated access to the same entry in
  // the hash table below, but it  seems alright in favor of readability.
  if (child_parent_table_.count(handle) == 0) {
    LOG(WARNING) << __func__ << ": handle does not exist.";
    return;
  }
  for (trunks::TPM_HANDLE parent : child_parent_table_[handle]) {
    --child_count_table_[parent];
    if (child_count_table_[parent] == 0) {
      child_count_table_.erase(parent);
      FlushHostHandle(parent);
    }
  }
  child_parent_table_.erase(handle);
}

}  // namespace vtpm
