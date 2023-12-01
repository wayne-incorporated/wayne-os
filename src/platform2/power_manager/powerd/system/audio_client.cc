// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/audio_client.h"

#include <algorithm>
#include <map>
#include <memory>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>

#include "power_manager/powerd/system/audio_observer.h"

namespace power_manager::system {

namespace {

// Maximum amount of time to wait for a reply from CRAS.
constexpr base::TimeDelta kCrasDBusTimeout = base::Seconds(3);

}  // namespace

// static
constexpr char AudioClient::kTypeKey[];
constexpr char AudioClient::kActiveKey[];
constexpr char AudioClient::kHeadphoneNodeType[];
constexpr char AudioClient::kHdmiNodeType[];
constexpr char AudioClient::kAudioSuspendedFile[];

AudioClient::AudioClient() : weak_ptr_factory_(this) {}

AudioClient::~AudioClient() {
  if (dbus_wrapper_)
    dbus_wrapper_->RemoveObserver(this);
}

void AudioClient::Init(DBusWrapperInterface* dbus_wrapper,
                       const base::FilePath& run_dir) {
  DCHECK(dbus_wrapper);
  dbus_wrapper_ = dbus_wrapper;
  dbus_wrapper_->AddObserver(this);
  audio_suspended_path_ = run_dir.Append(kAudioSuspendedFile);

  cras_proxy_ = dbus_wrapper_->GetObjectProxy(cras::kCrasServiceName,
                                              cras::kCrasServicePath);
  dbus_wrapper_->RegisterForServiceAvailability(
      cras_proxy_, base::BindOnce(&AudioClient::HandleCrasAvailableOrRestarted,
                                  weak_ptr_factory_.GetWeakPtr()));

  typedef void (AudioClient::*SignalMethod)(dbus::Signal*);
  const std::map<const char*, SignalMethod> kSignalMethods = {
      {cras::kNodesChanged, &AudioClient::HandleNodesChangedSignal},
      {cras::kActiveOutputNodeChanged,
       &AudioClient::HandleActiveOutputNodeChangedSignal},
      {cras::kNumberOfActiveStreamsChanged,
       &AudioClient::HandleNumberOfActiveStreamsChangedSignal},
      {cras::kAudioOutputActiveStateChanged,
       &AudioClient::HandleAudioOutputActiveStateChangedSignal},
  };
  for (const auto& it : kSignalMethods) {
    dbus_wrapper_->RegisterForSignal(
        cras_proxy_, cras::kCrasControlInterface, it.first,
        base::BindRepeating(it.second, weak_ptr_factory_.GetWeakPtr()));
  }

  if (base::PathExists(audio_suspended_path_))
    SetSuspended(false);
}

bool AudioClient::GetHeadphoneJackPlugged() const {
  return headphone_jack_plugged_;
}

bool AudioClient::GetHdmiActive() const {
  return hdmi_active_;
}

void AudioClient::AddObserver(AudioObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void AudioClient::RemoveObserver(AudioObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

void AudioClient::SetSuspended(bool suspended) {
  dbus::MethodCall method_call(cras::kCrasControlInterface,
                               cras::kSetSuspendAudio);
  dbus::MessageWriter writer(&method_call);
  writer.AppendBool(suspended);
  dbus_wrapper_->CallMethodSync(cras_proxy_, &method_call, kCrasDBusTimeout);
  if (suspended) {
    if (base::WriteFile(audio_suspended_path_, nullptr, 0) < 0)
      PLOG(ERROR) << "Couldn't create " << audio_suspended_path_.value();
  } else {
    if (!base::DeleteFile(audio_suspended_path_))
      PLOG(ERROR) << "Couldn't delete " << audio_suspended_path_.value();
  }
}

void AudioClient::OnDBusNameOwnerChanged(const std::string& service_name,
                                         const std::string& old_owner,
                                         const std::string& new_owner) {
  if (service_name == cras::kCrasServiceName && !new_owner.empty()) {
    LOG(INFO) << "D-Bus " << service_name << " ownership changed to "
              << new_owner;
    HandleCrasAvailableOrRestarted(true);
  }
}

bool AudioClient::IsAudioActive() const {
  return num_output_streams_ > 0 && output_active_;
}

void AudioClient::CallGetNodes() {
  dbus::MethodCall method_call(cras::kCrasControlInterface, cras::kGetNodes);
  dbus_wrapper_->CallMethodAsync(
      cras_proxy_, &method_call, kCrasDBusTimeout,
      base::BindOnce(&AudioClient::HandleGetNodesResponse,
                     weak_ptr_factory_.GetWeakPtr()));
}

void AudioClient::HandleGetNodesResponse(dbus::Response* response) {
  if (!response)
    return;

  const bool old_headphone_jack_plugged = headphone_jack_plugged_;
  const bool old_hdmi_active = hdmi_active_;

  headphone_jack_plugged_ = false;
  hdmi_active_ = false;

  // At the outer level, there's a dictionary corresponding to each audio node.
  dbus::MessageReader response_reader(response);
  dbus::MessageReader node_reader(nullptr);
  while (response_reader.PopArray(&node_reader)) {
    std::string type;
    bool active = false;

    // Iterate over the dictionary's entries.
    dbus::MessageReader property_reader(nullptr);
    while (node_reader.PopDictEntry(&property_reader)) {
      std::string key;
      if (!property_reader.PopString(&key)) {
        LOG(WARNING) << "Skipping dictionary entry with non-string key";
        continue;
      }
      if (key == kTypeKey) {
        if (!property_reader.PopVariantOfString(&type))
          LOG(WARNING) << kTypeKey << " key has non-string value";
      } else if (key == kActiveKey) {
        if (!property_reader.PopVariantOfBool(&active))
          LOG(WARNING) << kActiveKey << " key has non-bool value";
      }
    }

    VLOG(1) << "Saw node: type=" << type << " active=" << active;

    // The D-Bus interface doesn't return unplugged nodes.
    if (type == kHeadphoneNodeType)
      headphone_jack_plugged_ = true;
    else if (type == kHdmiNodeType && active)
      hdmi_active_ = true;
  }

  if (headphone_jack_plugged_ != old_headphone_jack_plugged ||
      hdmi_active_ != old_hdmi_active) {
    LOG(INFO) << "Updated audio devices: headphones "
              << (headphone_jack_plugged_ ? "" : "un") << "plugged, "
              << "HDMI " << (hdmi_active_ ? "" : "in") << "active";
  }
}

void AudioClient::CallGetNumberOfActiveOutputStreams() {
  dbus::MethodCall method_call(cras::kCrasControlInterface,
                               cras::kGetNumberOfActiveOutputStreams);
  dbus_wrapper_->CallMethodAsync(
      cras_proxy_, &method_call, kCrasDBusTimeout,
      base::BindOnce(&AudioClient::HandleGetNumberOfActiveOutputStreamsResponse,
                     weak_ptr_factory_.GetWeakPtr()));
}

void AudioClient::HandleGetNumberOfActiveOutputStreamsResponse(
    dbus::Response* response) {
  if (!response)
    return;

  int num_output_streams = 0;
  if (!dbus::MessageReader(response).PopInt32(&num_output_streams)) {
    LOG(WARNING) << "Unable to read " << cras::kGetNumberOfActiveOutputStreams
                 << " args";
    return;
  }

  VLOG(1) << "Output stream count changed to " << num_output_streams;
  UpdateAudioState(num_output_streams, output_active_);
}

void AudioClient::CallIsAudioOutputActive() {
  dbus::MethodCall method_call(cras::kCrasControlInterface,
                               cras::kIsAudioOutputActive);
  dbus_wrapper_->CallMethodAsync(
      cras_proxy_, &method_call, kCrasDBusTimeout,
      base::BindOnce(&AudioClient::HandleIsAudioOutputActiveResponse,
                     weak_ptr_factory_.GetWeakPtr()));
}

void AudioClient::HandleIsAudioOutputActiveResponse(dbus::Response* response) {
  if (!response)
    return;

  int32_t output_active = 0;
  if (!dbus::MessageReader(response).PopInt32(&output_active)) {
    LOG(WARNING) << "Unable to read " << cras::kIsAudioOutputActive << " args";
    return;
  }

  VLOG(1) << "Output-active state is " << output_active;
  UpdateAudioState(num_output_streams_, output_active > 0);
}

void AudioClient::HandleCrasAvailableOrRestarted(bool available) {
  if (!available) {
    LOG(ERROR) << "Failed waiting for CRAS to become available";
    return;
  }
  CallGetNodes();
  CallGetNumberOfActiveOutputStreams();
  CallIsAudioOutputActive();
}

void AudioClient::HandleNodesChangedSignal(dbus::Signal* signal) {
  CallGetNodes();
}

void AudioClient::HandleActiveOutputNodeChangedSignal(dbus::Signal* signal) {
  CallGetNodes();
}

void AudioClient::HandleNumberOfActiveStreamsChangedSignal(
    dbus::Signal* signal) {
  // The signal only contains the total count of streams (i.e. both input and
  // output), so we need to call the method to get the output stream count.
  CallGetNumberOfActiveOutputStreams();
}

void AudioClient::HandleAudioOutputActiveStateChangedSignal(
    dbus::Signal* signal) {
  bool output_active = false;
  if (!dbus::MessageReader(signal).PopBool(&output_active)) {
    LOG(WARNING) << "Failed to read " << cras::kAudioOutputActiveStateChanged
                 << " args";
    return;
  }

  VLOG(1) << "Output-active state changed to " << output_active;
  UpdateAudioState(num_output_streams_, output_active);
}

void AudioClient::UpdateAudioState(int num_output_streams, bool output_active) {
  const bool was_active = IsAudioActive();
  num_output_streams_ = num_output_streams;
  output_active_ = output_active;
  const bool is_active = IsAudioActive();

  if (is_active != was_active) {
    for (AudioObserver& observer : observers_)
      observer.OnAudioStateChange(is_active);
  }
}

}  // namespace power_manager::system
