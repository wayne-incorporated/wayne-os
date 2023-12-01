// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AUDIO_CLIENT_INTERFACE_H_
#define POWER_MANAGER_POWERD_SYSTEM_AUDIO_CLIENT_INTERFACE_H_

#include "power_manager/powerd/system/audio_observer.h"

namespace power_manager::system {

// Interface for monitoring system audio activity.
class AudioClientInterface {
 public:
  AudioClientInterface() = default;
  AudioClientInterface(const AudioClientInterface&) = delete;
  AudioClientInterface& operator=(const AudioClientInterface&) = delete;

  virtual ~AudioClientInterface() = default;

  // Returns the current state of the headphone jack and of HDMI audio.
  virtual bool GetHeadphoneJackPlugged() const = 0;
  virtual bool GetHdmiActive() const = 0;

  // Adds or removes an observer.
  virtual void AddObserver(AudioObserver* observer) = 0;
  virtual void RemoveObserver(AudioObserver* observer) = 0;

  // Suspends or resumes the audio according to the value of |suspended|.
  virtual void SetSuspended(bool suspended) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AUDIO_CLIENT_INTERFACE_H_
