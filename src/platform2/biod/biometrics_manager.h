// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOMETRICS_MANAGER_H_
#define BIOD_BIOMETRICS_MANAGER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <base/base64.h>
#include <base/functional/callback.h>
#include <chromeos/dbus/service_constants.h>
#include <base/strings/string_util.h>

#include "base/time/time.h"
#include "biod/biometrics_manager_record.h"
#include "biod/proto_bindings/constants.pb.h"
#include "biod/proto_bindings/messages.pb.h"
#include "biod/session.h"

namespace biod {

// A BiometricsManager object represents one biometric input device and all of
// the records registered with it. At a high level, there are 3 operations that
// are supported: 1) enrolling new record objects, 2) authenticating against
// those record objects, and 3) destroying all record objects made from this
// BiometricsManager. For DestroyAllRecords the operation is as simple as
// calling the function. For the other operations, the BiometricsManager object
// must be entered into AuthSession or EnrollSession, which is represented
// in code by the return of the session objects. EnrollSession and AuthSession
// can be thought of as session objects that are ongoing as long as the unique
// pointers remain in scope and the End/Cancel methods haven't been called. It's
// undefined what StartEnrollSession or StartAuthSession will do if there is an
// valid outstanding EnrollSession or AuthSession object in the wild.
class BiometricsManager {
 public:
  struct EnrollSessionEnder {
    void operator()(BiometricsManager* biometrics_manager) {
      biometrics_manager->EndEnrollSession();
    }
  };

  struct AuthSessionEnder {
    void operator()(BiometricsManager* biometrics_manager) {
      biometrics_manager->EndAuthSession();
    }
  };

  // Returned by StartEnrollSession to ensure that EnrollSession eventually
  // ends.
  using EnrollSession = Session<EnrollSessionEnder>;

  // Returned by StartAuthSession to ensure that AuthSession eventually
  // ends.
  using AuthSession = Session<AuthSessionEnder>;

  virtual ~BiometricsManager() {}
  virtual BiometricType GetType() = 0;

  // Puts this BiometricsManager into EnrollSession mode, which can be ended by
  // letting the returned session fall out of scope. The user_id is arbitrary
  // and is given to AuthScanDone callbacks in the AuthSession object. The label
  // should be human readable and ideally from the user themselves. The label
  // can be read and modified from the Record objects. This will fail if ANY
  // other mode is active. Returns a false EnrollSession on failure.
  virtual EnrollSession StartEnrollSession(std::string user_id,
                                           std::string label) = 0;

  // Puts this BiometricsManager into AuthSession mode, which can be ended by
  // letting the returned session fall out of scope. This will fail if ANY other
  // mode is active. Returns a false AuthSession on failure.
  virtual AuthSession StartAuthSession() = 0;

  // Gets the records successfully loaded to the biometrics device (eg. FPMCU).
  // Records that are invalid, with unsupported version, belongs to different
  // user or not successfully loaded to the biometrics device, are not included
  // in the returned vector.
  virtual std::vector<std::unique_ptr<BiometricsManagerRecord>>
  GetLoadedRecords() = 0;

  // Irreversibly destroys records registered with this BiometricsManager,
  // including currently encrypted ones. Returns true if successful.
  // TODO(mqg): right now it does not destroy the encrypted records, but that is
  // the goal for the future.
  virtual bool DestroyAllRecords() = 0;

  // Remove all decrypted records from memory. Still keep them in storage.
  virtual void RemoveRecordsFromMemory() = 0;

  // Read all the records for one user. Return true if successful.
  virtual bool ReadRecordsForSingleUser(const std::string& user_id) = 0;

  virtual void ScheduleMaintenance(const base::TimeDelta& delta) = 0;

  // The callbacks should remain valid as long as this object is valid.

  // Enrollment progress passed to EnrollScanDoneCallback.
  struct EnrollStatus {
    // True if enrollment is complete (which may take multiple scans).
    bool done;
    // Percentage of the enrollment process that is complete, in the range [0,
    // 100]. -1 if the sensor library did not provide a percentage.
    int percent_complete;
  };
  // Invoked from EnrollSession mode whenever the user attempts a scan. The
  // first parameter ScanResult tells whether the scan was successful. The
  // second parameter EnrollStatus indicates whether the enrollment is complete.
  // It may take multiple successful scans before enrollment is complete.  When
  // the record is complete, EnrollSession mode will automatically be ended.
  using EnrollScanDoneCallback =
      base::RepeatingCallback<void(ScanResult, const EnrollStatus&)>;
  virtual void SetEnrollScanDoneHandler(
      const EnrollScanDoneCallback& on_enroll_scan_done) = 0;

  // Invoked from AuthSession mode to indicate either a bad scan of any kind, or
  // a successful scan. In the case of successful scan, AttemptMatches is a map
  // of user id keys to a vector of record id values.
  using AttemptMatches =
      std::unordered_map<std::string, std::vector<std::string>>;
  using AuthScanDoneCallback =
      base::RepeatingCallback<void(FingerprintMessage, AttemptMatches)>;
  virtual void SetAuthScanDoneHandler(
      const AuthScanDoneCallback& on_auth_scan_done) = 0;

  // Invoked during any session to indicate that the session has ended with
  // failure. Any EnrollSession record that was underway is thrown away and
  // AuthSession will no longer be happening.
  using SessionFailedCallback = base::RepeatingCallback<void()>;
  virtual void SetSessionFailedHandler(
      const SessionFailedCallback& on_session_failed) = 0;

  virtual bool SendStatsOnLogin() { return true; }

  // Set whether the biometrics manager can access the underlying disk storage
  // for reading/writing records.
  virtual void SetDiskAccesses(bool allow) {}

  // Perform a reset on the underlying sensor h/w (as well as re-initialize any
  // software state associated with that sensor).
  virtual bool ResetSensor() { return true; }

  // Perform the reset of any internal key/secret which is used for local
  // encryption of data handled by the biometrics manager.
  // If |factory_init| is true, we do not actually reset the secret, only
  // initialise one if hadn't been initialised before.
  virtual bool ResetEntropy(bool factory_init) = 0;

 protected:
  virtual void EndEnrollSession() = 0;
  virtual void EndAuthSession() = 0;
};
}  // namespace biod

#endif  // BIOD_BIOMETRICS_MANAGER_H_
