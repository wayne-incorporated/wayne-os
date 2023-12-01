// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMASTER_KEYMASTER_SERVER_H_
#define ARC_KEYMASTER_KEYMASTER_SERVER_H_

#include <memory>
#include <vector>

#include <base/location.h>
#include <base/memory/scoped_refptr.h>
#include <base/threading/thread.h>
#include <keymaster/android_keymaster.h>
#include <mojo/cert_store.mojom.h>
#include <mojo/keymaster.mojom.h>

#include "arc/keymaster/context/arc_keymaster_context.h"

namespace arc {
namespace keymaster {

// KeymasterServer is a Mojo implementation of the Keymaster 3 HIDL interface.
// It fulfills requests using the reference Android Keymaster implementation.
class KeymasterServer : public arc::mojom::KeymasterServer {
 public:
  KeymasterServer();
  // Not copyable nor assignable.
  KeymasterServer(const KeymasterServer&) = delete;
  KeymasterServer& operator=(const KeymasterServer&) = delete;
  ~KeymasterServer() override;

  void UpdateContextPlaceholderKeys(std::vector<mojom::ChromeOsKeyPtr> keys,
                                    base::OnceCallback<void(bool)> callback);

  base::WeakPtr<KeymasterServer> GetWeakPtr() {
    return weak_ptr_factory_.GetWeakPtr();
  }

  // mojom::KeymasterServer overrides.
  void SetSystemVersion(uint32_t osVersion, uint32_t osPatchLevel) override;

  void AddRngEntropy(const std::vector<uint8_t>& data,
                     AddRngEntropyCallback callback) override;

  void GetKeyCharacteristics(
      ::arc::mojom::GetKeyCharacteristicsRequestPtr request,
      GetKeyCharacteristicsCallback callback) override;

  void GenerateKey(std::vector<::arc::mojom::KeyParameterPtr> key_params,
                   GenerateKeyCallback callback) override;

  void ImportKey(arc::mojom::ImportKeyRequestPtr request,
                 ImportKeyCallback callback) override;

  void ExportKey(arc::mojom::ExportKeyRequestPtr request,
                 ExportKeyCallback callback) override;

  void AttestKey(arc::mojom::AttestKeyRequestPtr request,
                 AttestKeyCallback callback) override;

  void UpgradeKey(arc::mojom::UpgradeKeyRequestPtr request,
                  UpgradeKeyCallback callback) override;

  void DeleteKey(const std::vector<uint8_t>& key_blob,
                 DeleteKeyCallback callback) override;

  void DeleteAllKeys(DeleteKeyCallback callback) override;

  void Begin(arc::mojom::BeginRequestPtr request,
             BeginCallback callback) override;

  void Update(arc::mojom::UpdateRequestPtr request,
              UpdateCallback callback) override;

  void Finish(arc::mojom::FinishRequestPtr request,
              FinishCallback callback) override;

  void Abort(uint64_t operationHandle, AbortCallback callback) override;

 private:
  class Backend {
   public:
    Backend();
    // Not copyable nor assignable.
    Backend(const Backend&) = delete;
    Backend& operator=(const Backend&) = delete;
    ~Backend();

    context::ArcKeymasterContext* context() { return context_; }

    ::keymaster::AndroidKeymaster* keymaster() { return &keymaster_; }

   private:
    // Owned by |keymaster_|.
    context::ArcKeymasterContext* context_;
    ::keymaster::AndroidKeymaster keymaster_;
  };

  // Runs the AndroidKeymaster operation |member| with |request| as input in the
  // background |backend_thread_|.
  //
  // The given |callback| is run with the output of the keymaster operation,
  // after being posted to the original task runner that called this method.
  template <typename KmMember, typename KmRequest, typename KmResponse>
  void RunKeymasterRequest(
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

  // Thread where Keymaster operations are executed.
  //
  // |base::Thread| guarantees that destruction waits until any leftover tasks
  // are executed, so this must be destroyed before |backend_| is.
  base::Thread backend_thread_;

  // Must be last member to ensure weak pointers are invalidated first.
  base::WeakPtrFactory<KeymasterServer> weak_ptr_factory_;
};

}  // namespace keymaster
}  // namespace arc

#endif  // ARC_KEYMASTER_KEYMASTER_SERVER_H_
