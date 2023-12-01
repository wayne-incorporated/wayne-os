// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "media_perception/device_management.pb.h"
#include "media_perception/fake_chrome_audio_service_client.h"
#include "media_perception/fake_rtanalytics.h"
#include "media_perception/fake_video_capture_service_client.h"
#include "media_perception/media_perception_impl.h"
#include "media_perception/proto_mojom_conversion.h"
#include "media_perception/serialized_proto.h"

namespace mri {
namespace {

class MediaPerceptionImplTest : public testing::Test {
 protected:
  void SetUp() override {
    fake_vidcap_client_ = new FakeVideoCaptureServiceClient();
    vidcap_client_ =
        std::shared_ptr<VideoCaptureServiceClient>(fake_vidcap_client_);
    fake_cras_client_ = new FakeChromeAudioServiceClient();
    cras_client_ = std::shared_ptr<ChromeAudioServiceClient>(fake_cras_client_);
    fake_rtanalytics_ = new FakeRtanalytics();
    rtanalytics_ = std::shared_ptr<Rtanalytics>(fake_rtanalytics_);
    media_perception_impl_ = std::make_unique<MediaPerceptionImpl>(
        media_perception_.BindNewPipeAndPassReceiver(), vidcap_client_,
        cras_client_, rtanalytics_);
  }

  mojo::Remote<chromeos::media_perception::mojom::MediaPerception>
      media_perception_;
  FakeVideoCaptureServiceClient* fake_vidcap_client_;
  std::shared_ptr<VideoCaptureServiceClient> vidcap_client_;
  FakeChromeAudioServiceClient* fake_cras_client_;
  std::shared_ptr<ChromeAudioServiceClient> cras_client_;
  FakeRtanalytics* fake_rtanalytics_;
  std::shared_ptr<Rtanalytics> rtanalytics_;
  std::unique_ptr<MediaPerceptionImpl> media_perception_impl_;
};

TEST_F(MediaPerceptionImplTest, TestGetVideoDevices) {
  bool get_devices_callback_done = false;
  media_perception_->GetVideoDevices(base::BindOnce(
      [](bool* get_devices_callback_done,
         std::vector<chromeos::media_perception::mojom::VideoDevicePtr>
             devices) {
        EXPECT_EQ(devices.size(), 0);
        *get_devices_callback_done = true;
      },
      &get_devices_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(get_devices_callback_done);

  // Set up a couple of fake devices.
  std::vector<SerializedVideoDevice> serialized_devices;
  VideoDevice device;
  device.set_id("1");
  serialized_devices.push_back(Serialized<VideoDevice>(device).GetBytes());
  device.set_id("2");
  serialized_devices.push_back(Serialized<VideoDevice>(device).GetBytes());
  fake_vidcap_client_->SetDevicesForGetDevices(serialized_devices);

  get_devices_callback_done = false;
  media_perception_->GetVideoDevices(base::BindOnce(
      [](bool* get_devices_callback_done,
         std::vector<chromeos::media_perception::mojom::VideoDevicePtr>
             devices) {
        EXPECT_EQ(devices.size(), 2);
        EXPECT_EQ(devices[0]->id, "1");
        EXPECT_EQ(devices[1]->id, "2");
        *get_devices_callback_done = true;
      },
      &get_devices_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(get_devices_callback_done);
}

TEST_F(MediaPerceptionImplTest, TestGetAudioDevices) {
  bool get_devices_callback_done = false;
  media_perception_->GetAudioDevices(base::BindOnce(
      [](bool* get_devices_callback_done,
         std::vector<chromeos::media_perception::mojom::AudioDevicePtr>
             devices) {
        EXPECT_EQ(devices.size(), 0);
        *get_devices_callback_done = true;
      },
      &get_devices_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(get_devices_callback_done);

  // Set up a couple of fake devices.
  std::vector<SerializedAudioDevice> serialized_devices;
  AudioDevice device;
  device.set_id("1");
  serialized_devices.push_back(Serialized<AudioDevice>(device).GetBytes());
  device.set_id("2");
  serialized_devices.push_back(Serialized<AudioDevice>(device).GetBytes());
  fake_cras_client_->SetDevicesForGetInputDevices(serialized_devices);

  get_devices_callback_done = false;
  media_perception_->GetAudioDevices(base::BindOnce(
      [](bool* get_devices_callback_done,
         std::vector<chromeos::media_perception::mojom::AudioDevicePtr>
             devices) {
        EXPECT_EQ(devices.size(), 2);
        EXPECT_EQ(devices[0]->id, "1");
        EXPECT_EQ(devices[1]->id, "2");
        *get_devices_callback_done = true;
      },
      &get_devices_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(get_devices_callback_done);
}

TEST_F(MediaPerceptionImplTest, TestSetupConfiguration) {
  bool setup_configuration_callback_done = false;

  media_perception_->SetupConfiguration(
      "test_configuration",
      base::BindOnce(
          [](bool* setup_configuration_callback_done,
             chromeos::media_perception::mojom::SuccessStatusPtr status,
             chromeos::media_perception::mojom::PerceptionInterfacesPtr
                 requests) {
            EXPECT_EQ(status->success, true);
            EXPECT_EQ(*status->failure_reason, "test_configuration");
            *setup_configuration_callback_done = true;
          },
          &setup_configuration_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(setup_configuration_callback_done);
}

TEST_F(MediaPerceptionImplTest, TestSetTemplateArguments) {
  bool set_template_arguments_callback_done = false;
  std::vector<uint8_t> arguments;

  media_perception_->SetTemplateArguments(
      "test_configuration", arguments,
      base::BindOnce(
          [](bool* set_template_arguments_callback_done,
             chromeos::media_perception::mojom::SuccessStatusPtr status) {
            EXPECT_EQ(status->success, true);
            EXPECT_EQ(*status->failure_reason, "test_configuration");
            *set_template_arguments_callback_done = true;
          },
          &set_template_arguments_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(set_template_arguments_callback_done);
}

TEST_F(MediaPerceptionImplTest, TestGetTemplateDevices) {
  DeviceTemplate template_one;
  template_one.set_template_name("one");
  DeviceTemplate template_two;
  template_two.set_template_name("two");
  std::vector<SerializedDeviceTemplate> device_templates;
  device_templates.push_back(
      Serialized<DeviceTemplate>(template_one).GetBytes());
  device_templates.push_back(
      Serialized<DeviceTemplate>(template_two).GetBytes());
  fake_rtanalytics_->SetSerializedDeviceTemplates(device_templates);

  bool get_template_devices_callback_done = false;
  media_perception_->GetTemplateDevices(
      "test_configuration",
      base::BindOnce(
          [](bool* get_template_devices_callback_done,
             std::vector<chromeos::media_perception::mojom::DeviceTemplatePtr>
                 device_templates) {
            EXPECT_EQ(device_templates.size(), 2);
            EXPECT_EQ(device_templates[0]->template_name, "one");
            EXPECT_EQ(device_templates[1]->template_name, "two");
            *get_template_devices_callback_done = true;
          },
          &get_template_devices_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(get_template_devices_callback_done);
}

TEST_F(MediaPerceptionImplTest, TestSetVideoDeviceForTemplateName) {
  bool callback_done = false;

  chromeos::media_perception::mojom::VideoDevicePtr video_device =
      chromeos::media_perception::mojom::VideoDevice::New();
  media_perception_->SetVideoDeviceForTemplateName(
      "test_configuration", "test_template", std::move(video_device),
      base::BindOnce(
          [](bool* callback_done,
             chromeos::media_perception::mojom::SuccessStatusPtr status) {
            EXPECT_EQ(status->success, true);
            EXPECT_EQ(*status->failure_reason, "test_template");
            *callback_done = true;
          },
          &callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(callback_done);
}

TEST_F(MediaPerceptionImplTest, TestSetAudioDeviceForTemplateName) {
  bool callback_done = false;

  chromeos::media_perception::mojom::AudioDevicePtr audio_device =
      chromeos::media_perception::mojom::AudioDevice::New();
  media_perception_->SetAudioDeviceForTemplateName(
      "test_configuration", "test_template", std::move(audio_device),
      base::BindOnce(
          [](bool* callback_done,
             chromeos::media_perception::mojom::SuccessStatusPtr status) {
            EXPECT_EQ(status->success, true);
            EXPECT_EQ(*status->failure_reason, "test_template");
            *callback_done = true;
          },
          &callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(callback_done);
}

TEST_F(MediaPerceptionImplTest, TestSetVirtualVideoDeviceForTemplateName) {
  bool callback_done = false;

  chromeos::media_perception::mojom::VirtualVideoDevicePtr video_device =
      chromeos::media_perception::mojom::VirtualVideoDevice::New();
  video_device->video_device =
      chromeos::media_perception::mojom::VideoDevice::New();
  media_perception_->SetVirtualVideoDeviceForTemplateName(
      "test_configuration", "test_template", std::move(video_device),
      base::BindOnce(
          [](bool* callback_done,
             chromeos::media_perception::mojom::SuccessStatusPtr status) {
            EXPECT_EQ(status->success, true);
            EXPECT_EQ(*status->failure_reason, "test_template");
            *callback_done = true;
          },
          &callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(callback_done);
}

TEST_F(MediaPerceptionImplTest, TestGetPipelineState) {
  bool get_pipeline_callback_done = false;

  media_perception_->GetPipelineState(
      "test_configuration",
      base::BindOnce(
          [](bool* get_pipeline_callback_done,
             chromeos::media_perception::mojom::PipelineStatePtr
                 pipeline_state) {
            EXPECT_EQ(
                pipeline_state->status,
                chromeos::media_perception::mojom::PipelineStatus::SUSPENDED);
            *get_pipeline_callback_done = true;
          },
          &get_pipeline_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(get_pipeline_callback_done);
}

TEST_F(MediaPerceptionImplTest, TestSetPipelineState) {
  bool set_pipeline_callback_done = false;

  chromeos::media_perception::mojom::PipelineStatePtr desired_pipeline_state =
      chromeos::media_perception::mojom::PipelineState::New();
  desired_pipeline_state->status =
      chromeos::media_perception::mojom::PipelineStatus::RUNNING;
  media_perception_->SetPipelineState(
      "test_configuration", std::move(desired_pipeline_state),
      base::BindOnce(
          [](bool* set_pipeline_callback_done,
             chromeos::media_perception::mojom::PipelineStatePtr
                 pipeline_state) {
            EXPECT_EQ(
                pipeline_state->status,
                chromeos::media_perception::mojom::PipelineStatus::RUNNING);
            *set_pipeline_callback_done = true;
          },
          &set_pipeline_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(set_pipeline_callback_done);
}

TEST_F(MediaPerceptionImplTest, TestGetGlobalPipelineState) {
  bool get_global_pipeline_callback_done = false;

  media_perception_->GetGlobalPipelineState(base::BindOnce(
      [](bool* get_global_pipeline_callback_done,
         chromeos::media_perception::mojom::GlobalPipelineStatePtr state) {
        EXPECT_EQ(*state->states[0]->configuration_name, "fake_configuration");
        *get_global_pipeline_callback_done = true;
      },
      &get_global_pipeline_callback_done));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(get_global_pipeline_callback_done);
}

}  // namespace
}  // namespace mri
