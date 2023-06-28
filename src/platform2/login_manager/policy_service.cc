// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/policy_service.h"

#include <stdint.h>

#include <set>
#include <string>
#include <utility>

#include <base/bind.h>
#include <base/callback.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/synchronization/waitable_event.h>
#include <brillo/message_loops/message_loop.h>
#include <chromeos/dbus/service_constants.h>

#include "bindings/device_management_backend.pb.h"
#include "login_manager/blob_util.h"
#include "login_manager/dbus_util.h"
#include "login_manager/nss_util.h"
#include "login_manager/policy_key.h"
#include "login_manager/policy_store.h"
#include "login_manager/resilient_policy_store.h"
#include "login_manager/system_utils.h"
#include "login_manager/validator_utils.h"

namespace em = enterprise_management;

namespace login_manager {

PolicyNamespace MakeChromePolicyNamespace() {
  return std::make_pair(POLICY_DOMAIN_CHROME, std::string());
}

// Returns true if the domain, when part of a PolicyNamespace, expects a
// non-empty |component_id()|.
bool IsComponentDomain(PolicyDomain domain) {
  switch (domain) {
    case POLICY_DOMAIN_CHROME:
      return false;
    case POLICY_DOMAIN_EXTENSIONS:
    case POLICY_DOMAIN_SIGNIN_EXTENSIONS:
      return true;
  }
  NOTREACHED();
  return false;
}

constexpr char PolicyService::kChromePolicyFileName[] = "policy";
constexpr char PolicyService::kExtensionsPolicyFileNamePrefix[] =
    "policy_extension_id_";
constexpr char PolicyService::kSignInExtensionsPolicyFileNamePrefix[] =
    "policy_signin_extension_id_";

PolicyService::PolicyService(const base::FilePath& policy_dir,
                             PolicyKey* policy_key,
                             LoginMetrics* metrics,
                             bool resilient_chrome_policy_store)
    : metrics_(metrics),
      policy_dir_(policy_dir),
      policy_key_(policy_key),
      resilient_chrome_policy_store_(resilient_chrome_policy_store),
      delegate_(nullptr),
      weak_ptr_factory_(this) {}

PolicyService::~PolicyService() = default;

bool PolicyService::Store(const PolicyNamespace& ns,
                          const std::vector<uint8_t>& policy_blob,
                          int key_flags,
                          SignatureCheck signature_check,
                          const Completion& completion) {
  em::PolicyFetchResponse policy;
  if (!policy.ParseFromArray(policy_blob.data(), policy_blob.size()) ||
      !policy.has_policy_data()) {
    completion.Run(CREATE_ERROR_AND_LOG(dbus_error::kSigDecodeFail,
                                        "Unable to parse policy protobuf."));
    return false;
  }

  return StorePolicy(ns, policy, key_flags, signature_check, completion);
}

bool PolicyService::Retrieve(const PolicyNamespace& ns,
                             std::vector<uint8_t>* policy_blob) {
  *policy_blob = SerializeAsBlob(GetOrCreateStore(ns)->Get());
  return true;
}

bool PolicyService::Delete(const PolicyNamespace& ns,
                           SignatureCheck signature_check) {
  // Don't delete Chrome user or device policy.
  if (!IsComponentDomain(ns.first)) {
    LOG(ERROR) << "Deletion only allowed for component policy.";
    return false;
  }

  // Don't delete signed policy.
  if (signature_check != SignatureCheck::kDisabled) {
    LOG(ERROR) << "Deletion of signed policy not allowed.";
    return false;
  }

  // Delete file on disk if it exists.
  if (!GetOrCreateStore(ns)->Delete()) {
    LOG(ERROR) << "Failed to delete store.";
    return false;
  }

  // Delete store.
  policy_stores_.erase(ns);

  return true;
}

std::vector<std::string> PolicyService::ListComponentIds(PolicyDomain domain) {
  // Get all component IDs from policy files stored on disk.
  std::vector<std::string> file_component_ids;
  switch (domain) {
    case POLICY_DOMAIN_CHROME:
      // Does not support component IDs, early out.
      return std::vector<std::string>();

    case POLICY_DOMAIN_EXTENSIONS:
      file_component_ids = FindComponentIds(kExtensionsPolicyFileNamePrefix,
                                            &ValidateExtensionId);
      break;

    case POLICY_DOMAIN_SIGNIN_EXTENSIONS:
      file_component_ids = FindComponentIds(
          kSignInExtensionsPolicyFileNamePrefix, &ValidateExtensionId);
      break;
  }

  // We might have missed some IDs from component policy that has not been
  // written out yet, so check the stores as well.
  std::set<std::string> component_ids(file_component_ids.begin(),
                                      file_component_ids.end());
  for (const auto& kv : policy_stores_) {
    const PolicyNamespace& ns = kv.first;
    const std::string& component_id = ns.second;
    const PolicyStore* store = kv.second.get();
    // Only count stores that actually have policy!
    if (ns.first == domain && store->Get().has_policy_data())
      component_ids.insert(component_id);
  }

  return std::vector<std::string>(component_ids.begin(), component_ids.end());
}

void PolicyService::PersistPolicy(const PolicyNamespace& ns,
                                  const Completion& completion) {
  const bool success = GetOrCreateStore(ns)->Persist();
  OnPolicyPersisted(completion,
                    success ? dbus_error::kNone : dbus_error::kSigEncodeFail);
}

void PolicyService::PersistAllPolicy() {
  for (const auto& kv : policy_stores_)
    kv.second->Persist();
}

PolicyStore* PolicyService::GetOrCreateStore(const PolicyNamespace& ns) {
  PolicyStoreMap::const_iterator iter = policy_stores_.find(ns);
  if (iter != policy_stores_.end())
    return iter->second.get();

  bool resilient =
      (ns == MakeChromePolicyNamespace() && resilient_chrome_policy_store_);
  std::unique_ptr<PolicyStore> store;
  if (resilient)
    store = std::make_unique<ResilientPolicyStore>(GetPolicyPath(ns), metrics_);
  else
    store = std::make_unique<PolicyStore>(GetPolicyPath(ns));

  store->EnsureLoadedOrCreated();
  PolicyStore* policy_store_ptr = store.get();
  policy_stores_[ns] = std::move(store);
  return policy_store_ptr;
}

void PolicyService::SetStoreForTesting(const PolicyNamespace& ns,
                                       std::unique_ptr<PolicyStore> store) {
  policy_stores_[ns] = std::move(store);
}

void PolicyService::PostPersistKeyTask() {
  brillo::MessageLoop::current()->PostTask(
      FROM_HERE,
      base::Bind(&PolicyService::PersistKey, weak_ptr_factory_.GetWeakPtr()));
}

void PolicyService::PostPersistPolicyTask(const PolicyNamespace& ns,
                                          const Completion& completion) {
  brillo::MessageLoop::current()->PostTask(
      FROM_HERE, base::Bind(&PolicyService::PersistPolicy,
                            weak_ptr_factory_.GetWeakPtr(), ns, completion));
}

bool PolicyService::StorePolicy(const PolicyNamespace& ns,
                                const em::PolicyFetchResponse& policy,
                                int key_flags,
                                SignatureCheck signature_check,
                                const Completion& completion) {
  if (signature_check == SignatureCheck::kDisabled) {
    GetOrCreateStore(ns)->Set(policy);
    PostPersistPolicyTask(ns, completion);
    return true;
  }

  // Determine if the policy has pushed a new owner key and, if so, set it.
  if (policy.has_new_public_key() && !key()->Equals(policy.new_public_key())) {
    // The policy contains a new key, and it is different from |key_|.
    std::vector<uint8_t> der = StringToBlob(policy.new_public_key());

    bool installed = false;
    if (key()->IsPopulated()) {
      if (policy.has_new_public_key_signature() && (key_flags & KEY_ROTATE)) {
        // Graceful key rotation.
        LOG(INFO) << "Attempting policy key rotation.";
        installed =
            key()->Rotate(der, StringToBlob(policy.new_public_key_signature()));
      }
    } else if (key_flags & KEY_INSTALL_NEW) {
      LOG(INFO) << "Attempting to install new policy key.";
      installed = key()->PopulateFromBuffer(der);
    }
    if (!installed && (key_flags & KEY_CLOBBER)) {
      LOG(INFO) << "Clobbering existing policy key.";
      installed = key()->ClobberCompromisedKey(der);
    }

    if (!installed) {
      completion.Run(CREATE_ERROR_AND_LOG(dbus_error::kPubkeySetIllegal,
                                          "Failed to install policy key!"));
      return false;
    }

    // If here, need to persist the key just loaded into memory to disk.
    PostPersistKeyTask();
  }

  // Validate signature on policy and persist to disk.
  if (!key()->Verify(StringToBlob(policy.policy_data()),
                     StringToBlob(policy.policy_data_signature()))) {
    completion.Run(CREATE_ERROR_AND_LOG(dbus_error::kVerifyFail,
                                        "Signature could not be verified."));
    return false;
  }

  GetOrCreateStore(ns)->Set(policy);
  PostPersistPolicyTask(ns, completion);
  return true;
}

void PolicyService::OnKeyPersisted(bool status) {
  if (status)
    LOG(INFO) << "Persisted policy key to disk.";
  else
    LOG(ERROR) << "Failed to persist policy key to disk.";
  if (delegate_)
    delegate_->OnKeyPersisted(status);
}

void PolicyService::OnPolicyPersisted(const Completion& completion,
                                      const std::string& dbus_error_code) {
  brillo::ErrorPtr error;
  if (dbus_error_code != dbus_error::kNone) {
    constexpr char kMessage[] = "Failed to persist policy to disk.";
    LOG(ERROR) << kMessage << ": " << dbus_error_code;
    error = CreateError(dbus_error_code, kMessage);
  }

  if (!completion.is_null())
    completion.Run(std::move(error));
  else
    error.reset();

  if (delegate_)
    delegate_->OnPolicyPersisted(dbus_error_code == dbus_error::kNone);
}

void PolicyService::PersistKey() {
  OnKeyPersisted(key()->Persist());
}

base::FilePath PolicyService::GetPolicyPath(const PolicyNamespace& ns) {
  // If the store has already been already created, return the store's path.
  PolicyStoreMap::const_iterator iter = policy_stores_.find(ns);
  if (iter != policy_stores_.end())
    return iter->second->policy_path();

  const PolicyDomain& domain = ns.first;
  const std::string& component_id = ns.second;
  switch (domain) {
    case POLICY_DOMAIN_CHROME:
      return policy_dir_.AppendASCII(kChromePolicyFileName);
    case POLICY_DOMAIN_EXTENSIONS:
      // Double-check extension ID (should have already been checked before).
      CHECK(ValidateExtensionId(component_id));
      return policy_dir_.AppendASCII(kExtensionsPolicyFileNamePrefix +
                                     component_id);
    case POLICY_DOMAIN_SIGNIN_EXTENSIONS:
      // Double-check extension ID (should have already been checked before).
      CHECK(ValidateExtensionId(component_id));
      return policy_dir_.AppendASCII(kSignInExtensionsPolicyFileNamePrefix +
                                     component_id);
  }
}

std::vector<std::string> PolicyService::FindComponentIds(
    const std::string& policy_filename_prefix, ComponentIdFilter filter) {
  std::vector<std::string> component_ids;
  base::FileEnumerator policy_files(policy_dir_, false /* recursive */,
                                    base::FileEnumerator::FILES,
                                    policy_filename_prefix + "*");
  base::FilePath policy_path;
  while (!(policy_path = policy_files.Next()).empty()) {
    const base::FilePath policy_filename = policy_path.BaseName();
    DCHECK_GE(policy_filename.value().size(), policy_filename_prefix.size());
    std::string component_id =
        policy_filename.value().substr(policy_filename_prefix.size());
    if (filter(component_id))
      component_ids.push_back(std::move(component_id));
  }
  return component_ids;
}

}  // namespace login_manager
