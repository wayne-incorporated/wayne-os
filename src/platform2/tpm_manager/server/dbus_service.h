// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_DBUS_SERVICE_H_
#define TPM_MANAGER_SERVER_DBUS_SERVICE_H_

#include <memory>

#include <base/functional/callback.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/dbus/dbus_signal.h>
#include <dbus/bus.h>

#include "tpm_manager/common/typedefs.h"
#include "tpm_manager/server/local_data_store.h"
#include "tpm_manager/server/tpm_manager_service.h"
#include "tpm_manager/server/tpm_nvram_interface.h"
#include "tpm_manager/server/tpm_ownership_interface.h"

namespace tpm_manager {

using brillo::dbus_utils::DBusMethodResponse;
using brillo::dbus_utils::DBusObject;
using brillo::dbus_utils::DBusSignal;

// Handles D-Bus communication with the TpmManager daemon.
class DBusService : public brillo::DBusServiceDaemon {
 public:
  // Constructs the instance with taking ownership of embedded
  // |tpm_manager_service|. With this constructor, this instance is also
  // responsible for initializing |tpm_manager_service|.
  DBusService(std::unique_ptr<TpmManagerService>&& tpm_manager_service,
              LocalDataStore* local_data_store);
  // Does not take ownership of |nvram_service|, |ownership_service|, or
  // |local_data_store|. The services and local data store provided must be
  // initialized, and must remain valid for the lifetime of this instance.
  DBusService(TpmNvramInterface* nvram_service,
              TpmOwnershipInterface* ownership_service,
              LocalDataStore* local_data_store);
  // Used to inject a mock bus.
  DBusService(scoped_refptr<dbus::Bus> bus,
              TpmNvramInterface* nvram_service,
              TpmOwnershipInterface* ownership_service,
              LocalDataStore* local_data_store);
  DBusService(const DBusService&) = delete;
  DBusService& operator=(const DBusService&) = delete;

  ~DBusService() override = default;

  // Registers objects exported by this service.
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

  // Callback function being called when ownership is (already) taken in
  // TpmInitializer.
  void NotifyOwnershipIsTaken();

  // Sends ownership taken signal to D-Bus if all the following conditions are
  // true:
  //  1. The signal has never been sent before.
  //  2. The signal is successfully registered in the TPM ownership interface.
  //  3. TPM ownership is already taken.
  //
  // Returns whether the signal was successfully sent.
  bool MaybeSendOwnershipTakenSignal();

 protected:
  // brillo::DBusServiceDaemon overrides
  int OnInit() override;

 private:
  friend class DBusServiceTest;

  template <typename RequestProtobufType,
            typename ReplyProtobufType,
            typename TpmInterface>
  using HandlerFunction = void (TpmInterface::*)(
      const RequestProtobufType&,
      base::OnceCallback<void(const ReplyProtobufType&)>);

  // Templates to handle D-Bus calls.
  template <typename RequestProtobufType,
            typename ReplyProtobufType,
            DBusService::HandlerFunction<RequestProtobufType,
                                         ReplyProtobufType,
                                         TpmNvramInterface> func>
  void HandleNvramDBusMethod(
      std::unique_ptr<DBusMethodResponse<const ReplyProtobufType&>> response,
      const RequestProtobufType& request);

  template <typename RequestProtobufType,
            typename ReplyProtobufType,
            DBusService::HandlerFunction<RequestProtobufType,
                                         ReplyProtobufType,
                                         TpmOwnershipInterface> func>
  void HandleOwnershipDBusMethod(
      std::unique_ptr<DBusMethodResponse<const ReplyProtobufType&>> response,
      const RequestProtobufType& request);

  std::unique_ptr<DBusObject> dbus_object_;
  std::unique_ptr<TpmManagerService> tpm_manager_service_;
  TpmNvramInterface* nvram_service_;
  TpmOwnershipInterface* ownership_service_;
  LocalDataStore* local_data_store_;

  bool ownership_already_taken_ = false;
  bool already_sent_ownership_taken_signal_ = false;

  // Pointer of the ownership taken signal. The signal is indirectly owned by
  // dbus_object_.
  std::weak_ptr<DBusSignal<OwnershipTakenSignal>> ownership_taken_signal_;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_DBUS_SERVICE_H_
