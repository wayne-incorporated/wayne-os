// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AUDIO_CLIENT_H_
#define POWER_MANAGER_POWERD_SYSTEM_AUDIO_CLIENT_H_

#include "power_manager/powerd/system/audio_client_interface.h"

#include <string>

#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>

#include "power_manager/powerd/system/dbus_wrapper.h"

namespace dbus {
class ObjectProxy;
class Response;
class Signal;
}  // namespace dbus

namespace power_manager::system {

// Real implementation of AudioClientInterface that monitors audio activity as
// reported by CRAS, the Chrome OS audio server.
class AudioClient : public AudioClientInterface,
                    public DBusWrapperInterface::Observer {
 public:
  // Keys within node dictionaries returned by CRAS.
  static constexpr char kTypeKey[] = "Type";
  static constexpr char kActiveKey[] = "Active";

  // Types assigned to headphone and HDMI nodes by CRAS.
  static constexpr char kHeadphoneNodeType[] = "HEADPHONE";
  static constexpr char kHdmiNodeType[] = "HDMI";

  // Basename appended to |run_dir| passed to Init() to produce
  // |audio_suspended_path_|.
  static constexpr char kAudioSuspendedFile[] = "audio_suspended";

  AudioClient();
  AudioClient(const AudioClient&) = delete;
  AudioClient& operator=(const AudioClient&) = delete;

  ~AudioClient() override;

  // Initializes the object. Ownership of |dbus_wrapper| remains with the
  // caller.
  void Init(DBusWrapperInterface* dbus_wrapper, const base::FilePath& run_dir);

  // AudioClientInterface:
  bool GetHeadphoneJackPlugged() const override;
  bool GetHdmiActive() const override;
  void AddObserver(AudioObserver* observer) override;
  void RemoveObserver(AudioObserver* observer) override;
  void SetSuspended(bool suspended) override;

  // DBusWrapperInterface::Observer:
  void OnDBusNameOwnerChanged(const std::string& service_name,
                              const std::string& old_owner,
                              const std::string& new_owner) override;

 private:
  // Computes the overall audio-active state based on |num_output_streams_| and
  // |output_active_|.
  bool IsAudioActive() const;

  // Asynchronously updates |headphone_jack_plugged_| and |hdmi_active_|.
  void CallGetNodes();
  void HandleGetNodesResponse(dbus::Response* response);

  // Asynchronously updates |num_output_streams_| and notifies observers.
  void CallGetNumberOfActiveOutputStreams();
  void HandleGetNumberOfActiveOutputStreamsResponse(dbus::Response* response);

  // Asynchronously updates |output_active_| and notifies observers.
  void CallIsAudioOutputActive();
  void HandleIsAudioOutputActiveResponse(dbus::Response* response);

  // Handles various events announced over D-Bus.
  void HandleCrasAvailableOrRestarted(bool available);
  void HandleNodesChangedSignal(dbus::Signal* signal);
  void HandleActiveOutputNodeChangedSignal(dbus::Signal* signal);
  void HandleNumberOfActiveStreamsChangedSignal(dbus::Signal* signal);
  void HandleAudioOutputActiveStateChangedSignal(dbus::Signal* signal);

  // Helper method used to set |num_output_streams_| and |output_active_| and
  // notify |observers_| if the overall audio-active state changed.
  void UpdateAudioState(int num_output_streams, bool output_active);

  DBusWrapperInterface* dbus_wrapper_ = nullptr;  // weak
  dbus::ObjectProxy* cras_proxy_ = nullptr;       // weak

  // Number of audio output streams currently open.
  int num_output_streams_ = 0;

  // True if there's at least one output stream that's receiving nonempty audio
  // data. Note that the CRAS-reported status may remain active for the order of
  // tens of seconds after output has actually ceased in order to reduce
  // spamminess and CPU utilization: https://crbug.com/753596
  bool output_active_ = false;

  // Is something plugged in to a headphone jack?
  bool headphone_jack_plugged_ = false;

  // Is an HDMI output active?
  bool hdmi_active_ = false;

  base::ObserverList<AudioObserver> observers_;

  // Path to a file that's touched when audio is suspended by sending D-Bus
  // method to cras and unlinked when the un-suspended. Used to detect cases
  // where powerd was restarted mid-suspend-attempt and didn't announce
  // un-suspend.
  base::FilePath audio_suspended_path_;

  base::WeakPtrFactory<AudioClient> weak_ptr_factory_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AUDIO_CLIENT_H_
