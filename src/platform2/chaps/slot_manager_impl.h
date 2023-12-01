// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_SLOT_MANAGER_IMPL_H_
#define CHAPS_SLOT_MANAGER_IMPL_H_

#include "chaps/handle_generator.h"
#include "chaps/slot_manager.h"
#include "chaps/slot_policy.h"
#include "chaps/system_shutdown_blocker.h"
#include "chaps/token_manager_interface.h"

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <libhwsec/frontend/chaps/frontend.h>

#include "chaps/chaps_factory.h"
#include "chaps/chaps_metrics.h"
#include "chaps/object_pool.h"

namespace chaps {

class SessionFactory;

// Maintains a list of PKCS #11 slots and modifies the list according to login
// events received. Sample usage:
//    SlotManagerImpl slot_manager(...);
//    if (!slot_manager.Init()) {
//      ...
//    }
//    // Ready for use by SlotManager clients.
class SlotManagerImpl : public SlotManager,
                        public TokenManagerInterface,
                        public HandleGenerator {
 public:
  SlotManagerImpl(ChapsFactory* factory,
                  const hwsec::ChapsFrontend* hwsec,
                  bool auto_load_system_token,
                  SystemShutdownBlocker* system_shutdown_blocker,
                  ChapsMetrics* chaps_metrics);
  SlotManagerImpl(const SlotManagerImpl&) = delete;
  SlotManagerImpl& operator=(const SlotManagerImpl&) = delete;

  ~SlotManagerImpl() override;

  // Initializes the slot manager. Returns true on success.
  virtual bool Init();

  // SlotManager methods.
  int GetSlotCount() override;
  bool IsTokenAccessible(const brillo::SecureBlob& isolate_credential,
                         int slot_id) const override;
  bool IsTokenPresent(const brillo::SecureBlob& isolate_credential,
                      int slot_id) const override;
  void GetSlotInfo(const brillo::SecureBlob& isolate_credential,
                   int slot_id,
                   CK_SLOT_INFO* slot_info) const override;
  void GetTokenInfo(const brillo::SecureBlob& isolate_credential,
                    int slot_id,
                    CK_TOKEN_INFO* token_info) const override;
  const MechanismMap* GetMechanismInfo(
      const brillo::SecureBlob& isolate_credential, int slot_id) const override;
  int OpenSession(const brillo::SecureBlob& isolate_credential,
                  int slot_id,
                  bool is_read_only) override;
  bool CloseSession(const brillo::SecureBlob& isolate_credential,
                    int session_id) override;
  void CloseAllSessions(const brillo::SecureBlob& isolate_credential,
                        int slot_id) override;
  bool GetSession(const brillo::SecureBlob& isolate_credential,
                  int session_id,
                  Session** session) const override;

  // TokenManagerInterface methods.
  bool OpenIsolate(brillo::SecureBlob* isolate_credential,
                   bool* new_isolate_created) override;
  void CloseIsolate(const brillo::SecureBlob& isolate_credential) override;
  bool LoadToken(const brillo::SecureBlob& isolate_credential,
                 const base::FilePath& path,
                 const brillo::SecureBlob& auth_data,
                 const std::string& label,
                 int* slot_id) override;
  bool UnloadToken(const brillo::SecureBlob& isolate_credential,
                   const base::FilePath& path) override;
  bool GetTokenPath(const brillo::SecureBlob& isolate_credential,
                    int slot_id,
                    base::FilePath* path) override;

  // HandleGenerator methods.
  int CreateHandle() override;

 private:
  // Holds all information associated with a particular isolate.
  struct Isolate {
    brillo::SecureBlob credential;
    int open_count;
    // The set of slots accessible through this isolate.
    std::set<int> slot_ids;
  };

  // Holds all information associated with a particular slot.
  struct Slot {
    CK_SLOT_INFO slot_info;
    CK_TOKEN_INFO token_info;
    std::shared_ptr<SlotPolicy> slot_policy;
    std::shared_ptr<ObjectPool> token_object_pool;
    // Key: A session identifier.
    // Value: The associated session object.
    std::map<int, std::shared_ptr<Session>> sessions;
  };

  // The HWSec object is enabled or not.
  bool HwsecIsEnabled();

  // The HWSec object is ready to use or not.
  bool HwsecIsReady();

  // Internal token presence check without isolate_credential check.
  bool IsTokenPresent(int slot_id) const;

  // Provides default PKCS #11 slot and token information. This method fills
  // the given information structures with constant default values formatted to
  // be PKCS #11 compliant.
  void GetDefaultInfo(CK_SLOT_INFO* slot_info, CK_TOKEN_INFO* token_info);

  // Initializes a key hierarchy for a particular token. This will clobber any
  // existing key hierarchy for the token. Returns true on success.
  //  slot_id - The slot of the token to be initialized.
  //  object_pool - This must be the token's persistent object pool; it will be
  //                used to store internal blobs related to the key hierarchy.
  //  auth_data - Authorization data to be used for the key hierarchy. This same
  //              data will be required to use the key hierarchy in the future.
  //  root_key - On success will be assigned the new root key for the token.
  bool InitializeKeyHierarchy(int slot_id,
                              ObjectPool* object_pool,
                              const std::string& auth_data,
                              std::string* root_key);

  // Searches for slot that does not currently contain a token. If no such slot
  // exists a new slot is created. The slot identifier of the empty slot is
  // returned.
  int FindEmptySlot();

  // Creates new slots.
  //  num_slots - The number of slots to be created.
  void AddSlots(int num_slots);

  // Creates a new isolate with the given isolate credential.
  void AddIsolate(const brillo::SecureBlob& isolate_credential);

  // Destroy isolate and unload any tokens in that isolate.
  void DestroyIsolate(const Isolate& isolate);

  // Get the path of the token loaded in the given slot.
  bool PathFromSlotId(int slot_id, base::FilePath* path) const;

  // Performs initialization tasks that depend on the HWSec status.
  // If the HWSec is not ready this cannot succeed.
  // These tasks include seeding the software prng and loading the system token.
  bool InitStage2();

  // Migrates software token to HWSec token if needed. Returns true when the
  // migration is needed. Return false in the other case.
  bool MigrateTokenIfNeeded(const base::FilePath& path,
                            const brillo::SecureBlob& auth_data,
                            std::shared_ptr<ObjectPool> object_pool);

  // LoadToken for internal callers.
  bool LoadTokenInternal(const brillo::SecureBlob& isolate_credential,
                         const base::FilePath& path,
                         const brillo::SecureBlob& auth_data,
                         const std::string& label,
                         int* slot_id);

  // Loads the root key for a HWSec token.
  void LoadHwsecToken(base::OnceCallback<void(bool)> callback,
                      int slot_id,
                      const base::FilePath& path,
                      const brillo::SecureBlob& auth_data,
                      std::shared_ptr<ObjectPool> object_pool);

  // Loads the root key for a HWSec token after the HWSec unseals data.
  void LoadHwsecTokenAfterUnseal(
      base::OnceCallback<void(bool)> callback,
      const base::FilePath& path,
      const brillo::SecureBlob& auth_data,
      std::shared_ptr<ObjectPool> object_pool,
      hwsec::StatusOr<brillo::SecureBlob> unsealed_data);

  // The final operation of loading the root key for a HWSec token.
  void LoadHwsecTokenFinal(base::OnceCallback<void(bool)> callback,
                           const base::FilePath& path,
                           const brillo::SecureBlob& auth_data,
                           std::shared_ptr<ObjectPool> object_pool,
                           brillo::SecureBlob root_key);

  // Initializes a new HWSec token.
  void InitializeHwsecToken(base::OnceCallback<void(bool)> callback,
                            const base::FilePath& path,
                            const brillo::SecureBlob& auth_data,
                            std::shared_ptr<ObjectPool> object_pool);

  // Initializes a new HWSec token after the secure element generated random.
  void InitializeHwsecTokenAfterGenerateRandom(
      base::OnceCallback<void(bool)> callback,
      const base::FilePath& path,
      const brillo::SecureBlob& auth_data,
      std::shared_ptr<ObjectPool> object_pool,
      hwsec::StatusOr<brillo::SecureBlob> random_data);

  // Initializes a new HWSec token with the specific root key.
  void InitializeHwsecTokenWithRootKey(base::OnceCallback<void(bool)> callback,
                                       const base::FilePath& path,
                                       const brillo::SecureBlob& auth_data,
                                       std::shared_ptr<ObjectPool> object_pool,
                                       brillo::SecureBlob root_key);

  // Initializes a new HWSec token after the secure element sealed the data.
  void InitializeHwsecTokenAfterSealData(
      base::OnceCallback<void(bool)> callback,
      const base::FilePath& path,
      const brillo::SecureBlob& auth_data,
      std::shared_ptr<ObjectPool> object_pool,
      brillo::SecureBlob root_key,
      hwsec::StatusOr<hwsec::ChapsSealedData> sealed_data);

  // Loads the root key for a software-only token.
  bool LoadSoftwareToken(const brillo::SecureBlob& auth_data,
                         ObjectPool* object_pool);

  // Initializes a new software-only token.
  bool InitializeSoftwareToken(const brillo::SecureBlob& auth_data,
                               ObjectPool* object_pool);

  bool IsSharedSlot(const base::FilePath& path);

  ChapsFactory* factory_;
  int last_handle_;
  MechanismMap mechanism_info_;
  // Key: A path to a token's storage directory.
  // Value: The identifier of the associated slot.
  std::map<base::FilePath, int> path_slot_map_;
  std::vector<Slot> slot_list_;
  // Key: A session identifier.
  // Value: The identifier of the associated slot.
  std::map<int, int> session_slot_map_;
  std::map<brillo::SecureBlob, Isolate> isolate_map_;
  const hwsec::ChapsFrontend* hwsec_;
  bool auto_load_system_token_;
  bool is_initialized_;
  std::optional<bool> hwsec_enabled_;
  bool hwsec_ready_;
  SystemShutdownBlocker* system_shutdown_blocker_;
  ChapsMetrics* chaps_metrics_;
};

}  // namespace chaps

#endif  // CHAPS_SLOT_MANAGER_IMPL_H_
