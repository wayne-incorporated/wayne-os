// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_POLICY_STORE_H_
#define LOGIN_MANAGER_POLICY_STORE_H_

#include <string>

#include <base/files/file_path.h>

#include "bindings/device_management_backend.pb.h"

namespace login_manager {
class PolicyKey;

// This class holds policy settings and takes care of reading from and writing
// it to a file on disk. The policy is represented as a PolicyFetchResponse
// protobuffer, which may contain per-device or per-user policy in its payload.
//
// If there is a policy on disk at creation time, we will load it along with its
// signature.  A new policy and its attendant signature can be set at any time
// and persisted to disk on-demand.
//
// THIS CLASS DOES NO SIGNATURE VALIDATION.
// However, derived classes like `ResilientPolicyStore` might perform
// signature validation.
class PolicyStore {
 public:
  explicit PolicyStore(const base::FilePath& policy_path);
  PolicyStore(const PolicyStore&) = delete;
  PolicyStore& operator=(const PolicyStore&) = delete;

  virtual ~PolicyStore();

  // Call LoadOrCreate() if it hasn't been called already. Returns the
  // (possibly cached) result from the LoadOrCreate() call.
  virtual bool EnsureLoadedOrCreated();

  virtual const enterprise_management::PolicyFetchResponse& Get() const;

  // Persist |policy_| to disk at |policy_file_|.
  // Returns false if there's an error while writing data.
  virtual bool Persist();

  // Clobber the stored policy with new data.
  virtual void Set(const enterprise_management::PolicyFetchResponse& policy);

  const base::FilePath policy_path() const { return policy_path_; }

  bool resilient_for_testing() const { return is_resilient_store_; }

 protected:
  PolicyStore(const base::FilePath& policy_path, bool is_resilient);

  // Load the signed policy off of disk into |policy_|. Returns true unless
  // there is a policy on disk and loading it fails.
  virtual bool LoadOrCreate();

  // Persist |policy_| to disk at |policy_path|.
  // Returns false if there's an error while writing data.
  bool PersistToPath(const base::FilePath& policy_path);

  // Whether the |policy_| object was explicitly changed for the purpose of
  // being persisted, but not persisted yet. Currently this happens only when
  // it is updated through Set() method.
  bool explicit_update_persist_pending_ = false;

  enterprise_management::PolicyFetchResponse policy_;
  const base::FilePath policy_path_;

  enum LoadResult { NOT_LOADED, LOAD_SUCCEEDED, LOAD_FAILED };
  LoadResult load_result_ = NOT_LOADED;

 private:
  // Load the signed policy off of disk into |policy_| from |policy_path|.
  // Returns true unless there is a policy on disk and loading it fails.
  bool LoadOrCreateFromPath(const base::FilePath& policy_path);

  // The type of policy store. If resilient, the latest policy data are stored
  // in multiple files.
  const bool is_resilient_store_;
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_POLICY_STORE_H_
