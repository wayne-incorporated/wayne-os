// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_MISSIVE_MISSIVE_SERVICE_H_
#define MISSIVE_MISSIVE_MISSIVE_SERVICE_H_

#include <memory>
#include <string>

#include <brillo/dbus/dbus_method_response.h>
#include <dbus/bus.h>
#include <featured/feature_library.h>

#include "missive/dbus/upload_client.h"
#include "missive/proto/interface.pb.h"
#include "missive/storage/storage_configuration.h"
#include "missive/storage/storage_module_interface.h"
#include "missive/storage/storage_uploader_interface.h"
#include "missive/util/status.h"

namespace reporting {

class MissiveService {
 public:
  MissiveService(const MissiveService&) = delete;
  MissiveService& operator=(const MissiveService&) = delete;
  virtual ~MissiveService() = default;

  virtual void StartUp(scoped_refptr<dbus::Bus> bus,
                       feature::PlatformFeaturesInterface* feature_lib,
                       base::OnceCallback<void(Status)> cb) = 0;
  virtual Status ShutDown() = 0;
  virtual void OnReady() const {}

  virtual void EnqueueRecord(
      const EnqueueRecordRequest& in_request,
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<EnqueueRecordResponse>>
          out_response) = 0;

  virtual void FlushPriority(
      const FlushPriorityRequest& in_request,
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<FlushPriorityResponse>>
          out_response) = 0;

  virtual void ConfirmRecordUpload(
      const ConfirmRecordUploadRequest& in_request,
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<ConfirmRecordUploadResponse>>
          out_response) = 0;

  virtual void UpdateEncryptionKey(
      const UpdateEncryptionKeyRequest& in_request,
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<UpdateEncryptionKeyResponse>>
          out_response) = 0;

 protected:
  MissiveService() = default;
};

}  // namespace reporting

#endif  // MISSIVE_MISSIVE_MISSIVE_SERVICE_H_
