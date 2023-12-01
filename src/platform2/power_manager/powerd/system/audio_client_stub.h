// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AUDIO_CLIENT_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_AUDIO_CLIENT_STUB_H_

#include <base/observer_list.h>

#include "power_manager/powerd/system/audio_client_interface.h"

namespace power_manager::system {

// Stub implementation of AudioClientInterface for use by tests.
class AudioClientStub : public AudioClientInterface {
 public:
  AudioClientStub();
  AudioClientStub(const AudioClientStub&) = delete;
  AudioClientStub& operator=(const AudioClientStub&) = delete;

  ~AudioClientStub() override;

  bool suspended() const { return suspended_; }

  void set_headphone_jack_plugged(bool plugged) {
    headphone_jack_plugged_ = plugged;
  }
  void set_hdmi_active(bool active) { hdmi_active_ = active; }

  // AudioClientInterface:
  bool GetHeadphoneJackPlugged() const override;
  bool GetHdmiActive() const override;
  void AddObserver(AudioObserver* observer) override;
  void RemoveObserver(AudioObserver* observer) override;
  void SetSuspended(bool suspended) override;

 private:
  bool headphone_jack_plugged_ = false;
  bool hdmi_active_ = false;
  bool suspended_ = false;

  base::ObserverList<AudioObserver> observers_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AUDIO_CLIENT_STUB_H_
