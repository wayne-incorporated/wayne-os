// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_CLIENT_MISSIVE_CLIENT_H_
#define MISSIVE_CLIENT_MISSIVE_CLIENT_H_

#include <base/component_export.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/sequence_checker.h>
#include <base/task/sequenced_task_runner.h>
#include <dbus/bus.h>

#include <missive/proto/record.pb.h>
#include <missive/proto/record_constants.pb.h>
#include <missive/util/status.h>

namespace reporting {

// D-Bus client for Missive service.
// Missive service provides a method for enterprise customers to locally encrypt
// and store |Record|s.
class COMPONENT_EXPORT(MISSIVE) MissiveClient {
 public:
  // Interface with testing functionality. Accessed through GetTestInterface(),
  // only implemented in the fake implementation.
  class TestInterface {
   protected:
    virtual ~TestInterface() = default;
  };

  MissiveClient(const MissiveClient& other) = delete;
  MissiveClient& operator=(const MissiveClient& other) = delete;

  // Creates and initializes the global instance. |bus| must not be null.
  static void Initialize(dbus::Bus* bus);

  // Destroys the global instance.
  static void Shutdown();

  // Returns the global instance which may be null if not initialized.
  static MissiveClient* Get();

  // Returns an interface for testing (fake only), or returns nullptr.
  virtual TestInterface* GetTestInterface() = 0;

  virtual void EnqueueRecord(
      const Priority priority,
      Record record,
      base::OnceCallback<void(Status)> completion_callback) = 0;
  virtual void Flush(const Priority priority,
                     base::OnceCallback<void(Status)> completion_callback) = 0;
  virtual void UpdateEncryptionKey(
      const SignedEncryptionInfo& encryption_info) = 0;
  virtual void ReportSuccess(const SequenceInformation& sequence_information,
                             bool force_confirm) = 0;
  virtual base::WeakPtr<MissiveClient> GetWeakPtr() = 0;

  // Returns sequenced task runner.
  scoped_refptr<base::SequencedTaskRunner> origin_task_runner() const;

 protected:
  // Initialize/Shutdown should be used instead.
  MissiveClient();
  virtual ~MissiveClient();

  // Sequenced task runner - must be first member of the class.
  scoped_refptr<base::SequencedTaskRunner> origin_task_runner_;
  SEQUENCE_CHECKER(origin_checker_);
};

}  // namespace reporting

#endif  // MISSIVE_CLIENT_MISSIVE_CLIENT_H_
