// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMINT_KEYMINT_SERVER_H_
#define ARC_KEYMINT_KEYMINT_SERVER_H_

#include <memory>
#include <vector>

#include <base/location.h>
#include <base/memory/scoped_refptr.h>
#include <base/threading/thread.h>
#include <keymaster/android_keymaster.h>
#include <mojo/cert_store.mojom.h>
#include <mojo/keymint.mojom.h>

#include "arc/keymint/context/arc_keymint_context.h"

namespace arc::keymint {

// KeyMintServer is a Mojo implementation of the KeyMint 2 AIDL interface.
// It fulfills requests using the reference ARC KeyMint implementation,
// which is derived from Android reference KeyMint implementation but
// uses Chaps for certain operations.
class KeyMintServer : public arc::mojom::keymint::KeyMintServer {
 public:
  KeyMintServer();
  // Not copyable nor assignable.
  KeyMintServer(const KeyMintServer&) = delete;
  KeyMintServer& operator=(const KeyMintServer&) = delete;
  ~KeyMintServer() override;

  void UpdateContextPlaceholderKeys(std::vector<mojom::ChromeOsKeyPtr> keys,
                                    base::OnceCallback<void(bool)> callback);

  base::WeakPtr<KeyMintServer> GetWeakPtr() {
    return weak_ptr_factory_.GetWeakPtr();
  }

  // mojom::KeyMintServer overrides.
  void SetSystemVersion(uint32_t android_version,
                        uint32_t android_patchLevel) override;

  void AddRngEntropy(const std::vector<uint8_t>& data,
                     AddRngEntropyCallback callback) override;

  void GetKeyCharacteristics(
      arc::mojom::keymint::GetKeyCharacteristicsRequestPtr request,
      GetKeyCharacteristicsCallback callback) override;

  void GenerateKey(arc::mojom::keymint::GenerateKeyRequestPtr request,
                   GenerateKeyCallback callback) override;

  void ImportKey(arc::mojom::keymint::ImportKeyRequestPtr request,
                 ImportKeyCallback callback) override;

  void ImportWrappedKey(arc::mojom::keymint::ImportWrappedKeyRequestPtr request,
                        ImportWrappedKeyCallback callback) override;

  void UpgradeKey(arc::mojom::keymint::UpgradeKeyRequestPtr request,
                  UpgradeKeyCallback callback) override;

  void DeleteKey(const std::vector<uint8_t>& key_blob,
                 DeleteKeyCallback callback) override;

  void DeleteAllKeys(DeleteAllKeysCallback callback) override;

  void DestroyAttestationIds(DestroyAttestationIdsCallback callback) override;

  void Begin(arc::mojom::keymint::BeginRequestPtr request,
             BeginCallback callback) override;

  void DeviceLocked(bool password_only,
                    arc::mojom::keymint::TimeStampTokenPtr timestamp_token,
                    DeviceLockedCallback callback) override;

  void EarlyBootEnded(EarlyBootEndedCallback callback) override;

  void ConvertStorageKeyToEphemeral(
      const std::vector<uint8_t>& storage_key_blob,
      ConvertStorageKeyToEphemeralCallback callback) override;

  void GetRootOfTrustChallenge(
      GetRootOfTrustChallengeCallback callback) override;

  void GetRootOfTrust(const std::vector<uint8_t>& challenge,
                      GetRootOfTrustCallback callback) override;

  void SendRootOfTrust(const std::vector<uint8_t>& root_of_trust,
                       SendRootOfTrustCallback callback) override;

  void UpdateAad(arc::mojom::keymint::UpdateAadRequestPtr request,
                 UpdateAadCallback callback) override;

  void Update(arc::mojom::keymint::UpdateRequestPtr request,
              UpdateCallback callback) override;

  void Finish(arc::mojom::keymint::FinishRequestPtr request,
              FinishCallback callback) override;

  void Abort(uint64_t op_handle, AbortCallback callback) override;

 private:
  class Backend {
   public:
    Backend();
    // Not copyable nor assignable.
    Backend(const Backend&) = delete;
    Backend& operator=(const Backend&) = delete;
    ~Backend();

    context::ArcKeyMintContext* context() { return context_; }

    ::keymaster::AndroidKeymaster* keymint() { return &keymint_; }

   private:
    context::ArcKeyMintContext* context_;  // Owned by |keymint_|.
    ::keymaster::AndroidKeymaster keymint_;
  };

  // Runs the AndroidKeyMint operation |member| with |request| as input in the
  // background |backend_thread_|.
  //
  // The given |callback| is run with the output of the keymaster operation,
  // after being posted to the original task runner that called this method.
  template <typename KmMember, typename KmRequest, typename KmResponse>
  void RunKeyMintRequest(
      const base::Location& location,
      KmMember member,
      std::unique_ptr<KmRequest> request,
      base::OnceCallback<void(std::unique_ptr<KmResponse>)> callback);

  // Encapsulates all fields that should only be accessed from the background
  // |backend_thread_|.
  //
  // This must be created before |backend_thread_| and outlive it. There are no
  // other thread safety requirements during construction or destruction.
  Backend backend_;

  // Thread where KeyMint operations are executed. Response is posted
  // on the mojo thread. This is done to keep the mojo thread responsive
  // to additional requests.
  //
  // |base::Thread| guarantees that destruction waits until any leftover tasks
  // are executed, so this must be destroyed before |backend_| is.
  base::Thread backend_thread_;

  // Must be last member to ensure weak pointers are invalidated first.
  base::WeakPtrFactory<KeyMintServer> weak_ptr_factory_;
};

}  // namespace arc::keymint

#endif  // ARC_KEYMINT_KEYMINT_SERVER_H_
