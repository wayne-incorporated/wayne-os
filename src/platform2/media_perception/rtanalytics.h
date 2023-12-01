// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_RTANALYTICS_H_
#define MEDIA_PERCEPTION_RTANALYTICS_H_

// This header needs to be buildable from both Google3 and outside, so it cannot
// rely on Google3 dependencies.

#include <functional>
#include <string>
#include <vector>

namespace mri {

// Typdefs for readability. Serialized protos are passed back and forth across
// the boundary between platform2 code and librtanalytics.so.
// Note that these aliases are guaranteed to always have this type.
using SerializedPerceptionInterfaces = std::vector<uint8_t>;
using SerializedSuccessStatus = std::vector<uint8_t>;
using SerializedTemplateArguments = std::vector<uint8_t>;
using SerializedPipelineState = std::vector<uint8_t>;
using SerializedGlobalPipelineState = std::vector<uint8_t>;
using SerializedDeviceTemplate = std::vector<uint8_t>;
using SerializedVideoDevice = std::vector<uint8_t>;
using SerializedAudioDevice = std::vector<uint8_t>;
using SerializedVirtualVideoDevice = std::vector<uint8_t>;
using PipelineOutputHandler = std::function<void(const std::vector<uint8_t>&)>;
using SerializedIndexedTransitionsResponse = std::vector<uint8_t>;

class Rtanalytics {
 public:
  virtual ~Rtanalytics() = default;

  // ------------------ Start of Media Perception Mojo API ---------------------

  // Asks the library to setup a particular configuration. Success status is
  // filled in by the library side. The return value is the list of perception
  // interfaces that are fulfilled by the current configuration. This function
  // can be called multiple times to setup multiple configurations.
  // |success_status| cannot be null. Each PerceptionInterface contains output
  // stream types so that the CrOS side can register appropriate output
  // handlers.
  virtual SerializedPerceptionInterfaces SetupConfiguration(
      const std::string& configuration_name,
      SerializedSuccessStatus* success_status) = 0;

  // Sets template arugments for a specified configuration. Arguments should be
  // passed as a serialized proto that is kept in sync between the MPS and a
  // client.
  virtual SerializedSuccessStatus SetTemplateArguments(
      const std::string& configuration_name,
      const SerializedTemplateArguments& serialized_arguments) = 0;

  // Returns the list of template names for devices that can be filled in for a
  // particular configuration that has been setup. If the configuration has not
  // been setup via |SetupConfiguration| the returned list will always be empty.
  virtual std::vector<SerializedDeviceTemplate> GetTemplateDevices(
      const std::string& configuration_name) const = 0;

  // Enables a client of rtanalytics to set the parameters for a video device
  // for a specified device template.
  virtual SerializedSuccessStatus SetVideoDeviceForTemplateName(
      const std::string& configuration_name,
      const std::string& template_name,
      const SerializedVideoDevice& video_device) = 0;

  // Enables a client of rtanalytics to set the parameters for an audio device
  // for a specified device template.
  virtual SerializedSuccessStatus SetAudioDeviceForTemplateName(
      const std::string& configuration_name,
      const std::string& template_name,
      const SerializedAudioDevice& audio_device) = 0;

  // Enables a client of rtanalytics to set the parameters for a virtual video
  // device for a specified device template.
  virtual SerializedSuccessStatus SetVirtualVideoDeviceForTemplateName(
      const std::string& configuration_name,
      const std::string& template_name,
      const SerializedVirtualVideoDevice& virtual_device) = 0;

  // Returns the pipeline state of the given configuation.
  virtual SerializedPipelineState GetPipelineState(
      const std::string& configuration_name) const = 0;

  // Sets the pipeline to the desired state and returns the new state.
  virtual SerializedPipelineState SetPipelineState(
      const std::string& configuration_name,
      const SerializedPipelineState& desired_state) = 0;

  // Returns states of all existing pipelines.
  virtual SerializedGlobalPipelineState GetGlobalPipelineState() const = 0;

  // ------------------- End of Media Perception Mojo API ----------------------

  // Sets a callback for an output stream of the given configuration.
  virtual SerializedSuccessStatus SetPipelineOutputHandler(
      const std::string& configuration_name,
      const std::string& output_stream,
      PipelineOutputHandler output_handler) = 0;

  // Asks for the active Falcon camera IP for a configuration name.
  virtual std::string GetFalconIp(const std::string& configuration_name) = 0;

  // Sends the response from the Falcon camera over D-Bus back to the processing
  // pipelines.
  virtual void RespondToFalconPtzTransition(
      const std::string& configuration_name,
      const SerializedIndexedTransitionsResponse& response) = 0;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_RTANALYTICS_H_
