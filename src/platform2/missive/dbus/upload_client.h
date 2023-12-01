// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_DBUS_UPLOAD_CLIENT_H_
#define MISSIVE_DBUS_UPLOAD_CLIENT_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/ref_counted_delete_on_sequence.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>
#include <dbus/bus.h>

#include "missive/proto/interface.pb.h"
#include "missive/proto/record.pb.h"
#include "missive/util/statusor.h"

namespace reporting {

// Abstract base class for upload client implementation and use.
// Derived from RefCountedDeleteOnSequence in order to allow weak pointers usage
// with it (weak pointer factory needs to be deleted on the same thread the weak
// pointers are dereferenced).
class UploadClient : public base::RefCountedDeleteOnSequence<UploadClient> {
 public:
  // The requestor will receive a response to their UploadEncryptedRequest via
  // the HandleUploadResponseCallback.
  using HandleUploadResponseCallback =
      base::OnceCallback<void(StatusOr<UploadEncryptedRecordResponse>)>;

  // Factory method for asynchronously creating a UploadClient on
  // bus->OriginThread.
  static void Create(
      scoped_refptr<dbus::Bus> bus,
      base::OnceCallback<void(StatusOr<scoped_refptr<UploadClient>>)> cb);

  // Utilizes DBus to send a list of encrypted records to Chrome. Caller can
  // expect a response via the |response_callback|.
  virtual void SendEncryptedRecords(
      std::vector<EncryptedRecord> records,
      bool need_encryption_keys,
      uint64_t remaining_storage_capacity,
      std::optional<uint64_t> new_events_rate,
      HandleUploadResponseCallback response_callback) = 0;

 protected:
  explicit UploadClient(scoped_refptr<base::SequencedTaskRunner> task_runner)
      : base::RefCountedDeleteOnSequence<UploadClient>(task_runner) {}
  virtual ~UploadClient() = default;

 private:
  friend class base::RefCountedDeleteOnSequence<UploadClient>;
  friend class base::DeleteHelper<UploadClient>;
};
}  // namespace reporting

#endif  // MISSIVE_DBUS_UPLOAD_CLIENT_H_
