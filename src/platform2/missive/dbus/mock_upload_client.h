// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_DBUS_MOCK_UPLOAD_CLIENT_H_
#define MISSIVE_DBUS_MOCK_UPLOAD_CLIENT_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/task/sequenced_task_runner.h>

#include "missive/dbus/upload_client.h"
#include "missive/proto/record.pb.h"

namespace reporting::test {

class MockUploadClient : public UploadClient {
 public:
  MockUploadClient()
      : UploadClient(base::SequencedTaskRunner::GetCurrentDefault()) {}

  MOCK_METHOD(void,
              SendEncryptedRecords,
              (std::vector<EncryptedRecord> records,
               bool need_encryption_keys,
               uint64_t remaining_storage_capacity,
               std::optional<uint64_t> new_events_rate,
               HandleUploadResponseCallback response_callback),
              (override));

 private:
  friend class base::RefCountedThreadSafe<MockUploadClient>;
  friend class base::DeleteHelper<MockUploadClient>;
};
}  // namespace reporting::test

#endif  // MISSIVE_DBUS_MOCK_UPLOAD_CLIENT_H_
