// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_CLIENT_TPM_MANAGER_UTILITY_H_
#define TPM_MANAGER_CLIENT_TPM_MANAGER_UTILITY_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/synchronization/lock.h>
#include <base/threading/thread.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#include "tpm_manager/client/tpm_ownership_signal_handler.h"
#include "tpm_manager/common/export.h"

namespace tpm_manager {

// A TpmUtility implementation for version-independent functions.
class TPM_MANAGER_EXPORT TpmManagerUtility
    : public TpmOwnershipTakenSignalHandler {
 public:
  using OwnershipCallback = base::RepeatingCallback<void()>;

  TpmManagerUtility() = default;
  // a constructor which enables injection of mock interfaces.
  TpmManagerUtility(org::chromium::TpmManagerProxyInterface* tpm_owner,
                    org::chromium::TpmNvramProxyInterface* tpm_nvram);
  TpmManagerUtility(const TpmManagerUtility&) = delete;
  TpmManagerUtility& operator=(const TpmManagerUtility&) = delete;

  ~TpmManagerUtility() override = default;

  // Initializes the worker thread and proxies of |tpm_manager| and returns
  // |true| if successful. Returns |false| if we cannot start
  // |tpm_manager_thread_| or tpm_manager's interfaces fail to initialize.
  //
  // Once returning |true|, the calls of this function afterwards return |true|
  // without mutating any data member.
  virtual bool Initialize();

  // Blocking call of |TpmOwnershipDBusProxy::TakeOwnership|. Returns |true| iff
  // the operation succeeds.
  virtual bool TakeOwnership();

  // Blocking call of |TpmOwnershipDBusProxy::GetTpmStatus|.
  // Returns |true| iff the operation succeeds. Once returning |true|,
  // |is_enabled| indicates if TPM is enabled, and |is_owned| indicates if TPM
  // is owned. |local_data| is the current |LocalData| stored in the
  // |tpm_manager| service.
  virtual bool GetTpmStatus(bool* is_enabled,
                            bool* is_owned,
                            LocalData* local_data);

  // Blocking call of |TpmOwnershipDBusProxy::GetTpmNonsensitiveStatus|.
  // Returns |true| iff the operation succeeds. Once returning |true|,
  // |is_enabled| indicates if TPM is enabled, |is_owned| indicates if TPM is
  // owned, |is_owner_password_present| indicates if the owner password is still
  // retained, and |has_reset_lock_permissions| indicates if the tpm manager is
  // capable of reset DA.
  virtual bool GetTpmNonsensitiveStatus(bool* is_enabled,
                                        bool* is_owned,
                                        bool* is_owner_password_present,
                                        bool* has_reset_lock_permissions);

  // Blocking call of |TpmOwnershipDBusProxy::GetVersionInfo|.
  // Returns true iff the operation succeeds. On success, various parts of
  // version info are stored in the output args respectively.
  virtual bool GetVersionInfo(uint32_t* family,
                              uint64_t* spec_level,
                              uint32_t* manufacturer,
                              uint32_t* tpm_model,
                              uint64_t* firmware_version,
                              std::string* vendor_specific);

  // Blocking call of
  // |TpmOwnershipDBusProxy::RemoveOwnerDependency|. Returns |true| iff the
  // operation succeeds. |dependency| is the idenitier of the dependency.
  virtual bool RemoveOwnerDependency(const std::string& dependency);

  // Blocking call of
  // |TpmOwnershipDBusProxy::ClearStoredOwnerPassword|. Returns |true| iff the
  // operation succeeds.
  virtual bool ClearStoredOwnerPassword();

  // Blocking call of |TpmOwnershipDBusProxy::GetDictionaryAttackInfo|. Returns
  // |true| iff the operation succeeds. Once returning |true|, |counter|,
  // |threshold|, |lockout| and |seconds_remaining| will set to the respective
  // values of received |GetDictionaryAttackInfoReply|.
  virtual bool GetDictionaryAttackInfo(int* counter,
                                       int* threshold,
                                       bool* lockout,
                                       int* seconds_remaining);

  // Blocking call of |TpmOwnershipDBusProxy::GetDictionaryAttackInfo|. Returns
  // |true| iff the operation succeeds.
  virtual bool ResetDictionaryAttackLock();

  // Blocking call of |TpmNvramDBusProxy::DefineSpace|. Returns
  // |true| iff the operation succeeds. This call sends a request to define
  // the nvram at |index|.
  virtual bool DefineSpace(uint32_t index,
                           size_t size,
                           bool write_define,
                           bool bind_to_pcr0,
                           bool firmware_readable);

  // Blocking call of |TpmNvramDBusProxy::DestroySpace|. Returns
  // |true| iff the operation succeeds. This call sends a request to destroy
  // the nvram at |index|.
  virtual bool DestroySpace(uint32_t index);

  // Blocking call of |TpmNvramDBusProxy::WriteSpace|. Returns
  // |true| iff the operation succeeds. This call sends a request to write the
  // content of the nvram at |index|. If |use_owner_auth| is set, the request
  // tells the service to use owner authorization. Note: currently the arbitrary
  // auth value is not supported since we got no use case for now.
  virtual bool WriteSpace(uint32_t index,
                          const std::string& data,
                          bool use_owner_auth);

  // Blocking call of |TpmNvramDBusProxy::ReadSpace|. Returns |true| iff
  // the operation succeeds. This call sends a request to read the content of
  // the nvram at |index| and stores the output data in |output|. If
  // |use_owner_auth| is set, the request tells the service to use owner
  // authorization. Note: currently the arbitrary auth value is not supported
  // since we got no use case for now.
  virtual bool ReadSpace(uint32_t index,
                         bool use_owner_auth,
                         std::string* output);

  // Blocking call of |TpmNvramDBusProxy::ListSpaces|. Returns
  // |true| iff the operation succeeds. This call stores the space id in
  // |spaces|.
  virtual bool ListSpaces(std::vector<uint32_t>* spaces);

  // Blocking call of |TpmNvramDBusProxy::GetSpaceInfo|. Returns
  // |true| iff the operation succeeds. This call stores |size|,
  // |is_read_locked|, |is_write_locked| information of nvram at |index|.
  virtual bool GetSpaceInfo(uint32_t index,
                            uint32_t* size,
                            bool* is_read_locked,
                            bool* is_write_locked,
                            std::vector<NvramSpaceAttribute>* attributes);

  // Blocking call of |TpmNvramDBusProxy::LockSpace|. Returns
  // |true| iff the operation succeeds. This call sends a request to lock
  // the nvram at |index|.
  virtual bool LockSpace(uint32_t index);

  // Gets the current status of the ownership taken signal. Returns |true| iff
  // the signal is connected, no matter if it's connected successfully or not.
  // |is_successful| indicates if the dbus signal connection is successful or
  // not. |has_received| indicates if this instance has received the ownership
  // taken signal. Once |has_received| is set as |true|,|local_data| gets
  // updated. Any output parameter will be ignored to be set if the value is
  // |nullptr|.
  virtual bool GetOwnershipTakenSignalStatus(bool* is_successful,
                                             bool* has_received,
                                             LocalData* local_data);

  // Add callback which would be trigger after got tpm ownership.
  virtual void AddOwnershipCallback(OwnershipCallback ownership_callback);

  // Get a singleton of tpm_manager utility. It would return nullptr when
  // initialize failed.
  // Using singleton would resolve the ownership data race of consumers.
  static TpmManagerUtility* GetSingleton();

  void OnOwnershipTaken(const OwnershipTakenSignal& signal) override;

  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool is_successful) override;

 private:
  // Tpm_manager communication thread class that cleans up after stopping.
  class TpmManagerThread : public base::Thread {
   public:
    explicit TpmManagerThread(TpmManagerUtility* utility)
        : base::Thread("tpm_manager_thread"), utility_(utility) {
      DCHECK(utility_);
    }
    TpmManagerThread(const TpmManagerThread&) = delete;
    TpmManagerThread& operator=(const TpmManagerThread&) = delete;

    ~TpmManagerThread() override { Stop(); }

   private:
    void CleanUp() override { utility_->ShutdownTask(); }

    TpmManagerUtility* const utility_;
  };

  // Initialization operation that must be performed on the tpm_manager
  // thread.
  void InitializationTask(base::WaitableEvent* completion);

  // Shutdown operation that must be performed on the tpm_manager thread.
  void ShutdownTask();

  // Sends a request to tpm_managerd proxy and waits for a response.
  //
  // Example usage:
  //
  // tpm_manager::TakeOwnershipReply reply;
  // SendProxyRequestAndWait(
  //     &tpm_manager::TpmOwnershipInterface::TakeOwnership,
  //     tpm_owner_, tpm_manager::GetTpmStatusRequest(), &reply);
  template <typename ReplyProtoType,
            typename ProxyType,
            typename RequestProtoType,
            typename MethodType>
  void SendProxyRequestAndWait(const MethodType& method,
                               ProxyType* const& proxy,
                               const RequestProtoType& request_proto,
                               ReplyProtoType* reply_proto);

  scoped_refptr<dbus::Bus> bus_;

  // |tpm_owner_| and |tpm_nvram_| typically point to |default_tpm_owner_| and
  // |default_tpm_nvram_| respectively, created/destroyed on the
  // |tpm_manager_thread_|. As such, should not be accessed after that thread
  // is stopped/destroyed.
  org::chromium::TpmManagerProxyInterface* tpm_owner_{nullptr};
  org::chromium::TpmNvramProxyInterface* tpm_nvram_{nullptr};

  // |default_tpm_owner_| and |default_tpm_nvram_| are created and destroyed
  // on the |tpm_manager_thread_|, and are not available after the thread is
  // stopped/destroyed.
  std::unique_ptr<org::chromium::TpmManagerProxy> default_tpm_owner_;
  std::unique_ptr<org::chromium::TpmNvramProxy> default_tpm_nvram_;

  // A message loop thread dedicated for asynchronous communication with
  // tpm_managerd. Declared last, so that it is destroyed before the
  // objects it uses.
  TpmManagerThread tpm_manager_thread_{this};

  // Data structures for the dbus signal handling.

  // |ownership_signal_lock_| is used when the signal-handling data is
  // accessed; the mutex is necessary because the user of this class could read
  // the signal data.
  base::Lock ownership_signal_lock_;

  // |ownership_signal_lock_| is used when the signal-handling data is
  // accessed; the mutex is necessary because the user of this class could read
  // the signal data.
  base::Lock ownership_callback_lock_;

  // Only uses |is_connected_| to indicate if we can rely on the dbus signal to
  // get the local data though it could mean "not connected", "being
  // connected". Note that |is_connected_| could also mean the connection has
  // been attempted but not successfully. For naming reference, see arguments of
  // |brillo::dbus_utils::ConnectToSignal|.
  bool is_connected_{false};

  // Records if it's a successful signal connection once connected.
  bool is_connection_successful_{false};

  // |ownership_taken_signal_| stores the data once the ownership
  // taken signal is received.
  std::optional<OwnershipTakenSignal> ownership_taken_signal_;

  std::vector<OwnershipCallback> ownership_callbacks_;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_CLIENT_TPM_MANAGER_UTILITY_H_
