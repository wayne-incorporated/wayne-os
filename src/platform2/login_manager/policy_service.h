// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_POLICY_SERVICE_H_
#define LOGIN_MANAGER_POLICY_SERVICE_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/callback.h>
#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <brillo/errors/error.h>
#include <chromeos/dbus/service_constants.h>

#include "login_manager/proto_bindings/policy_descriptor.pb.h"

namespace enterprise_management {
class PolicyFetchResponse;
}

namespace login_manager {

class LoginMetrics;
class PolicyKey;
class PolicyStore;

// Whether policy signature must be checked in PolicyService::Store().
enum class SignatureCheck { kEnabled, kDisabled };

// Policies are namespaced by domain and component ID.
using PolicyNamespace = std::pair<PolicyDomain, std::string>;

// Returns the namespace for Chrome policies.
extern PolicyNamespace MakeChromePolicyNamespace();

// Manages policy storage and retrieval from underlying PolicyStores, thereby
// enforcing policy signatures against a given policy key. Also handles key
// rotations in case a new policy payload comes with an updated policy key.
// Policies are namespaced to allow storing different policy types (Chrome,
// extensions) with the same service. There is one store per namespace.
class PolicyService {
 public:
  // File name of Chrome policy.
  static const char kChromePolicyFileName[];
  // Prefix of the filename of extension policy. The full file name is suffixed
  // by the extension ID.
  static const char kExtensionsPolicyFileNamePrefix[];
  // Prefix of the filename of sign-in extension policy. The full file name is
  // suffixed by the extension ID.
  static const char kSignInExtensionsPolicyFileNamePrefix[];

  // Flags determining what do to with new keys in Store().
  enum KeyInstallFlags {
    KEY_NONE = 0,         // No key changes allowed.
    KEY_ROTATE = 1,       // Existing key may be rotated.
    KEY_INSTALL_NEW = 2,  // Allow to install a key if none is present.
    KEY_CLOBBER = 4,      // OK to replace the existing key without any checks.
  };

  // Callback for asynchronous completion of a Store operation.
  // On success, |error| is nullptr. Otherwise, it contains an instance
  // with detailed info.
  using Completion = base::Callback<void(brillo::ErrorPtr error)>;

  // Delegate for notifications about key and policy getting persisted.
  class Delegate {
   public:
    virtual ~Delegate() = default;
    virtual void OnPolicyPersisted(bool success) = 0;
    virtual void OnKeyPersisted(bool success) = 0;
  };

  // Constructor. |policy_dir| is the directory where policy is stored.
  // |policy_key| is the key for policy validation.
  // |metrics| is transferred to policy stores created by this instance.
  // |resilient_chrome_policy_store| is used to decide if the policy store has
  // to be created with backup files for resilience.
  PolicyService(const base::FilePath& policy_dir,
                PolicyKey* policy_key,
                LoginMetrics* metrics,
                bool resilient_chrome_policy_store);
  PolicyService(const PolicyService&) = delete;
  PolicyService& operator=(const PolicyService&) = delete;

  virtual ~PolicyService();

  // Stores a new policy under the namespace |ns|. If mandated by
  // |signature_check|, verifies the passed-in policy blob against the policy
  // key (if it exists), takes care of key rotation if required and persists
  // everything to disk. The |key_flags| parameter determines what to do with a
  // new key present in the policy, see KeyInstallFlags for possible values.
  //
  // Returns false on immediate errors. Otherwise, returns true and reports the
  // status of the operation through |completion|.
  virtual bool Store(const PolicyNamespace& ns,
                     const std::vector<uint8_t>& policy_blob,
                     int key_flags,
                     SignatureCheck signature_check,
                     const Completion& completion);

  // Retrieves the current policy blob (does not verify the signature) from the
  // namespace |ns|. Returns true on success.
  virtual bool Retrieve(const PolicyNamespace& ns,
                        std::vector<uint8_t>* policy_blob);

  // Deletes the policy for the namespace |ns|. This operation is only allowed
  // if |ns| specifies a component policy namespace (e.g. extensions) and if the
  // |signature_check| is disabled. Returns true on success.
  virtual bool Delete(const PolicyNamespace& ns,
                      SignatureCheck signature_check);

  // Returns a list of all component IDs in the given |domain| for which policy
  // is stored. Returns an empty vector if |domain| does not support component
  // IDs (e.g. POLICY_DOMAIN_CHROME).
  virtual std::vector<std::string> ListComponentIds(PolicyDomain domain);

  // Persists policy of the namespace |ns| to disk synchronously and passes
  // |completion| and the result to OnPolicyPersisted().
  virtual void PersistPolicy(const PolicyNamespace& ns,
                             const Completion& completion);

  // Persists policy for all namespaces.
  virtual void PersistAllPolicy();

  // Sets the policystore for namespace |ns|. Deletes the previous store if it
  // exists.
  void SetStoreForTesting(const PolicyNamespace& ns,
                          std::unique_ptr<PolicyStore> store);

  // Accessors for the delegate. PolicyService doesn't own the delegate, thus
  // client code must make sure that the delegate pointer stays valid.
  void set_delegate(Delegate* delegate) { delegate_ = delegate; }
  Delegate* delegate() { return delegate_; }

 protected:
  friend class PolicyServiceTest;

  // Returns a pointer to the policy store for the given namespace |ns|. Creates
  // the store if it does not exist yet and makes sure it's loaded or created.
  PolicyStore* GetOrCreateStore(const PolicyNamespace& ns);

  PolicyKey* key() { return policy_key_; }
  void set_policy_key_for_test(PolicyKey* key) { policy_key_ = key; }

  // Posts a task to run PersistKey().
  void PostPersistKeyTask();

  // Posts a task to run PersistPolicy().
  void PostPersistPolicyTask(const PolicyNamespace& ns,
                             const Completion& completion);

  // Store a policy blob under the namespace |ns|. This does the heavy lifting
  // for Store(), making the signature checks, taking care of key changes and
  // persisting policy and key data to disk.
  bool StorePolicy(const PolicyNamespace& ns,
                   const enterprise_management::PolicyFetchResponse& policy,
                   int key_flags,
                   SignatureCheck signature_check,
                   const Completion& completion);

  // Handles completion of a key storage operation, reporting the result to
  // |delegate_|.
  virtual void OnKeyPersisted(bool status);

  // Finishes persisting policy, notifying |delegate_| and reporting the
  // |dbus_error_code| through |completion|. |completion| may be null, and in
  // that case the reporting part is not done. |dbus_error_code| is a dbus_error
  // constant and can be a non-error, like kNone.
  void OnPolicyPersisted(const Completion& completion,
                         const std::string& dbus_error_code);

  // Owned by the caller. Passed to the policy stores at creation and used by
  // device policy service.
  LoginMetrics* metrics_ = nullptr;

 private:
  // Persists key() to disk synchronously and passes the result to
  // OnKeyPersisted().
  void PersistKey();

  // Returns the file path of the policy for the given namespace |ns|.
  base::FilePath GetPolicyPath(const PolicyNamespace& ns);

  using ComponentIdFilter = bool (*)(const std::string& component_id);

  // Returns the component ID parts of all policy filenames in |policy_dir_|
  // that start with |policy_filename_prefix|. IDs where |filter| returns false
  // are filtered out.
  std::vector<std::string> FindComponentIds(
      const std::string& policy_filename_prefix, ComponentIdFilter filter);

  using PolicyStoreMap =
      std::map<PolicyNamespace, std::unique_ptr<PolicyStore>>;
  PolicyStoreMap policy_stores_;
  base::FilePath policy_dir_;
  PolicyKey* policy_key_ = nullptr;
  bool resilient_chrome_policy_store_ = false;
  Delegate* delegate_ = nullptr;

  // Put at the last member, so that inflight weakptrs will be invalidated
  // before other members' destruction.
  base::WeakPtrFactory<PolicyService> weak_ptr_factory_;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_POLICY_SERVICE_H_
