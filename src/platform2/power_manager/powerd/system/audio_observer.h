// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AUDIO_OBSERVER_H_
#define POWER_MANAGER_POWERD_SYSTEM_AUDIO_OBSERVER_H_

#include <base/observer_list_types.h>

namespace power_manager::system {

// Interface for classes interested in observing audio activity detected by
// the AudioDetector class.
class AudioObserver : public base::CheckedObserver {
 public:
  ~AudioObserver() override = default;

  // Called when audio activity starts or stops.
  virtual void OnAudioStateChange(bool active) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AUDIO_OBSERVER_H_
