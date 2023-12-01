// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_DBUS_UPLOAD_CLIENT_IMPL_H_
#define MISSIVE_DBUS_UPLOAD_CLIENT_IMPL_H_

#include "missive/dbus/upload_client.h"

#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/ref_counted_delete_on_sequence.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>

#include "missive/proto/interface.pb.h"
#include "missive/proto/record.pb.h"
#include "missive/util/disconnectable_client.h"
#include "missive/util/statusor.h"

namespace reporting {

class UploadClientImpl : public UploadClient {
 public:
  // Factory method for asynchronously creating a UploadClientImpl with
  // specified |bus| and |chrome_proxy| on bus->OriginThread().
  static void Create(
      scoped_refptr<dbus::Bus> bus,
      dbus::ObjectProxy* chrome_proxy,
      base::OnceCallback<void(StatusOr<scoped_refptr<UploadClientImpl>>)> cb);

  // Utilizes DBus to send a list of encrypted records to Chrome. Caller can
  // expect a response via the |response_callback|.
  void SendEncryptedRecords(
      std::vector<EncryptedRecord> records,
      bool need_encryption_keys,
      uint64_t remaining_storage_capacity,
      std::optional<uint64_t> new_events_rate,
      HandleUploadResponseCallback response_callback) override;

  // Sets availability for testing only.
  void SetAvailabilityForTest(bool is_available);

 protected:
  UploadClientImpl(scoped_refptr<dbus::Bus> bus,
                   dbus::ObjectProxy* chrome_proxy);
  ~UploadClientImpl() override;

  void HandleUploadEncryptedRecordResponse(
      const std::unique_ptr<dbus::MethodCall> call,  // owned thru response.
      HandleUploadResponseCallback response_callback,
      dbus::Response* response) const;

 private:
  friend class base::RefCountedDeleteOnSequence<UploadClientImpl>;
  friend class base::DeleteHelper<UploadClientImpl>;
  void MaybeMakeCall(std::vector<EncryptedRecord> records,
                     const bool need_encryption_keys,
                     uint64_t remaining_storage_capacity,
                     std::optional<uint64_t> new_events_rate,
                     HandleUploadResponseCallback response_callback);

  // Returns disconnectable client, creating it if not created yet.
  // Must be called on task runner.
  DisconnectableClient* GetDisconnectableClient();

  void OwnerChanged(const std::string& old_owner, const std::string& new_owner);

  void ServerAvailable(bool service_is_available);

  scoped_refptr<dbus::Bus> const bus_;
  dbus::ObjectProxy* const chrome_proxy_;

  std::unique_ptr<DisconnectableClient, base::OnTaskRunnerDeleter> client_;

  // Note: This should remain the last member so it'll be destroyed and
  // invalidate its weak pointers before any other members are destroyed.
  base::WeakPtrFactory<UploadClientImpl> weak_ptr_factory_{this};
};
}  // namespace reporting

#endif  // MISSIVE_DBUS_UPLOAD_CLIENT_IMPL_H_
