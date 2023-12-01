// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_POWERD_EVENT_SERVICE_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_POWERD_EVENT_SERVICE_H_

#include <base/observer_list_types.h>

namespace diagnostics {
namespace wilco {

class PowerdEventService {
 public:
  class Observer : public base::CheckedObserver {
   public:
    enum class PowerEventType {
      // Energy consuming from external power source has been started.
      kAcInsert,
      // Energy consuming from external power source has been stopped.
      kAcRemove,
      // System has received suspend request.
      kOsSuspend,
      // System has completed suspend request.
      kOsResume,
    };

    virtual ~Observer() = default;

    virtual void OnPowerdEvent(PowerEventType type) = 0;
  };

  virtual ~PowerdEventService() = default;

  virtual void AddObserver(Observer* observer) = 0;
  virtual void RemoveObserver(Observer* observer) = 0;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_POWERD_EVENT_SERVICE_H_
