// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/run_loop.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "media_perception/fake_rtanalytics.h"
#include "media_perception/frame_perception.pb.h"
#include "media_perception/hotword_detection.pb.h"
#include "media_perception/output_manager.h"
#include "media_perception/presence_perception.pb.h"
#include "media_perception/proto_mojom_conversion.h"
#include "media_perception/serialized_proto.h"

namespace mri {
namespace {

class FramePerceptionHandlerImpl
    : public chromeos::media_perception::mojom::FramePerceptionHandler {
 public:
  FramePerceptionHandlerImpl(
      mojo::PendingReceiver<
          chromeos::media_perception::mojom::FramePerceptionHandler> receiver)
      : receiver_(this, std::move(receiver)) {
    EXPECT_TRUE(receiver_.is_bound());
  }

  void OnFramePerception(chromeos::media_perception::mojom::FramePerceptionPtr
                             frame_perception) override {
    frame_perception_ = ToProto(frame_perception);
  }

  FramePerception frame_perception_;

  mojo::Receiver<chromeos::media_perception::mojom::FramePerceptionHandler>
      receiver_;
};

class HotwordDetectionHandlerImpl
    : public chromeos::media_perception::mojom::HotwordDetectionHandler {
 public:
  HotwordDetectionHandlerImpl(
      mojo::PendingReceiver<
          chromeos::media_perception::mojom::HotwordDetectionHandler> receiver)
      : receiver_(this, std::move(receiver)) {
    EXPECT_TRUE(receiver_.is_bound());
  }

  void OnHotwordDetection(chromeos::media_perception::mojom::HotwordDetectionPtr
                              hotword_detection) override {
    hotword_detection_ = ToProto(hotword_detection);
  }

  HotwordDetection hotword_detection_;

  mojo::Receiver<chromeos::media_perception::mojom::HotwordDetectionHandler>
      receiver_;
};

class PresencePerceptionHandlerImpl
    : public chromeos::media_perception::mojom::PresencePerceptionHandler {
 public:
  PresencePerceptionHandlerImpl(
      mojo::PendingReceiver<
          chromeos::media_perception::mojom::PresencePerceptionHandler>
          receiver)
      : receiver_(this, std::move(receiver)) {
    EXPECT_TRUE(receiver_.is_bound());
  }

  void OnPresencePerception(
      chromeos::media_perception::mojom::PresencePerceptionPtr
          presence_perception) override {
    presence_perception_ = ToProto(presence_perception);
  }

  PresencePerception presence_perception_;

  mojo::Receiver<chromeos::media_perception::mojom::PresencePerceptionHandler>
      receiver_;
};

class OccupancyTriggerHandlerImpl
    : public chromeos::media_perception::mojom::OccupancyTriggerHandler {
 public:
  OccupancyTriggerHandlerImpl(
      mojo::PendingReceiver<
          chromeos::media_perception::mojom::OccupancyTriggerHandler> receiver)
      : receiver_(this, std::move(receiver)) {
    EXPECT_TRUE(receiver_.is_bound());
  }

  void OnOccupancyTrigger(chromeos::media_perception::mojom::OccupancyTriggerPtr
                              occupancy_trigger) override {
    occupancy_trigger_ = ToProto(occupancy_trigger);
  }

  OccupancyTrigger occupancy_trigger_;

  mojo::Receiver<chromeos::media_perception::mojom::OccupancyTriggerHandler>
      receiver_;
};

class AppearancesHandlerImpl
    : public chromeos::media_perception::mojom::AppearancesHandler {
 public:
  AppearancesHandlerImpl(
      mojo::PendingReceiver<
          chromeos::media_perception::mojom::AppearancesHandler> receiver)
      : receiver_(this, std::move(receiver)) {
    EXPECT_TRUE(receiver_.is_bound());
  }

  void OnAppearances(const std::vector<uint8_t>& appearances) override {
    appearances_ = appearances;
  }

  std::vector<uint8_t> appearances_;

  mojo::Receiver<chromeos::media_perception::mojom::AppearancesHandler>
      receiver_;
};

class OneTouchAutozoomHandlerImpl
    : public chromeos::media_perception::mojom::OneTouchAutozoomHandler {
 public:
  OneTouchAutozoomHandlerImpl(
      mojo::PendingReceiver<
          chromeos::media_perception::mojom::OneTouchAutozoomHandler> receiver)
      : receiver_(this, std::move(receiver)) {
    EXPECT_TRUE(receiver_.is_bound());
  }

  void OnSmartFraming(const std::vector<uint8_t>& smart_framing) override {
    smart_framing_ = smart_framing;
  }

  std::vector<uint8_t> smart_framing_;

  mojo::Receiver<chromeos::media_perception::mojom::OneTouchAutozoomHandler>
      receiver_;
};

class SoftwareAutozoomHandlerImpl
    : public chromeos::media_perception::mojom::SoftwareAutozoomHandler {
 public:
  SoftwareAutozoomHandlerImpl(
      mojo::PendingReceiver<
          chromeos::media_perception::mojom::SoftwareAutozoomHandler> receiver)
      : receiver_(this, std::move(receiver)) {
    EXPECT_TRUE(receiver_.is_bound());
  }

  void OnSmartFraming(const std::vector<uint8_t>& smart_framing) override {
    smart_framing_ = smart_framing;
  }

  std::vector<uint8_t> smart_framing_;

  mojo::Receiver<chromeos::media_perception::mojom::SoftwareAutozoomHandler>
      receiver_;
};

class OutputManagerTest : public testing::Test {
 protected:
  void SetUp() override {
    fake_rtanalytics_ = new FakeRtanalytics();
    rtanalytics_ = std::shared_ptr<Rtanalytics>(fake_rtanalytics_);
  }

  FakeRtanalytics* fake_rtanalytics_;
  std::shared_ptr<Rtanalytics> rtanalytics_;
};

TEST_F(OutputManagerTest, FramePerceptionOutputManagerTest) {
  PerceptionInterfaces perception_interfaces;
  PerceptionInterface* interface = perception_interfaces.add_interface();
  interface->set_interface_type(
      PerceptionInterfaceType::INTERFACE_FRAME_PERCEPTION);
  PipelineOutput* output = interface->add_output();
  output->set_output_type(PipelineOutputType::OUTPUT_FRAME_PERCEPTION);
  output->set_stream_name("fake_stream_name");

  chromeos::media_perception::mojom::PerceptionInterfacesPtr interfaces_ptr =
      chromeos::media_perception::mojom::PerceptionInterfaces::New();
  OutputManager output_manager("fake_frame_perception_configuration",
                               rtanalytics_, perception_interfaces,
                               &interfaces_ptr);
  // Verify that the mojo interface was created correctly.
  EXPECT_TRUE(interfaces_ptr->frame_perception_handler_request.is_valid());
  EXPECT_EQ(fake_rtanalytics_->GetMostRecentOutputStreamName(),
            "fake_stream_name");

  FramePerceptionHandlerImpl frame_perception_handler_impl(
      std::move(interfaces_ptr->frame_perception_handler_request));
  base::RunLoop().RunUntilIdle();

  FramePerception frame_perception;
  frame_perception.set_frame_id(1);
  output_manager.HandleFramePerception(
      Serialized<FramePerception>(frame_perception).GetBytes());
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(frame_perception_handler_impl.frame_perception_.frame_id(), 1);
}

TEST_F(OutputManagerTest, HotwordDetectionOutputManagerTest) {
  PerceptionInterfaces perception_interfaces;
  PerceptionInterface* interface = perception_interfaces.add_interface();
  interface->set_interface_type(
      PerceptionInterfaceType::INTERFACE_HOTWORD_DETECTION);
  PipelineOutput* output = interface->add_output();
  output->set_output_type(PipelineOutputType::OUTPUT_HOTWORD_DETECTION);
  output->set_stream_name("fake_stream_name");

  chromeos::media_perception::mojom::PerceptionInterfacesPtr interfaces_ptr =
      chromeos::media_perception::mojom::PerceptionInterfaces::New();
  OutputManager output_manager("fake_hotword_detection_configuration",
                               rtanalytics_, perception_interfaces,
                               &interfaces_ptr);
  // Verify that the mojo interface was created correctly.
  EXPECT_TRUE(interfaces_ptr->hotword_detection_handler_request.is_valid());
  EXPECT_EQ(fake_rtanalytics_->GetMostRecentOutputStreamName(),
            "fake_stream_name");

  HotwordDetectionHandlerImpl hotword_detection_handler_impl(
      std::move(interfaces_ptr->hotword_detection_handler_request));
  base::RunLoop().RunUntilIdle();

  HotwordDetection hotword_detection;
  hotword_detection.add_hotwords()->set_type(HotwordType::OK_GOOGLE);
  output_manager.HandleHotwordDetection(
      Serialized<HotwordDetection>(hotword_detection).GetBytes());
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(
      hotword_detection_handler_impl.hotword_detection_.hotwords(0).type(),
      HotwordType::OK_GOOGLE);
}

TEST_F(OutputManagerTest, PresencePerceptionOutputManagerTest) {
  PerceptionInterfaces perception_interfaces;
  PerceptionInterface* interface = perception_interfaces.add_interface();
  interface->set_interface_type(
      PerceptionInterfaceType::INTERFACE_PRESENCE_PERCEPTION);
  PipelineOutput* output = interface->add_output();
  output->set_output_type(PipelineOutputType::OUTPUT_PRESENCE_PERCEPTION);
  output->set_stream_name("fake_stream_name");

  chromeos::media_perception::mojom::PerceptionInterfacesPtr interfaces_ptr =
      chromeos::media_perception::mojom::PerceptionInterfaces::New();
  OutputManager output_manager("fake_presence_perception_configuration",
                               rtanalytics_, perception_interfaces,
                               &interfaces_ptr);
  // Verify that the mojo interface was created correctly.
  EXPECT_TRUE(interfaces_ptr->presence_perception_handler_request.is_valid());
  EXPECT_EQ(fake_rtanalytics_->GetMostRecentOutputStreamName(),
            "fake_stream_name");

  PresencePerceptionHandlerImpl presence_perception_handler_impl(
      std::move(interfaces_ptr->presence_perception_handler_request));
  base::RunLoop().RunUntilIdle();

  PresencePerception presence_perception;
  presence_perception.set_timestamp_us(1);
  output_manager.HandlePresencePerception(
      Serialized<PresencePerception>(presence_perception).GetBytes());
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(
      presence_perception_handler_impl.presence_perception_.timestamp_us(), 1);
}

TEST_F(OutputManagerTest, OccupancyTriggerOutputManagerTest) {
  PerceptionInterfaces perception_interfaces;
  PerceptionInterface* interface = perception_interfaces.add_interface();
  interface->set_interface_type(
      PerceptionInterfaceType::INTERFACE_OCCUPANCY_TRIGGER);
  PipelineOutput* output = interface->add_output();
  output->set_output_type(PipelineOutputType::OUTPUT_OCCUPANCY_TRIGGER);
  output->set_stream_name("fake_stream_name");

  chromeos::media_perception::mojom::PerceptionInterfacesPtr interfaces_ptr =
      chromeos::media_perception::mojom::PerceptionInterfaces::New();
  OutputManager output_manager("fake_presence_perception_configuration",
                               rtanalytics_, perception_interfaces,
                               &interfaces_ptr);
  // Verify that the mojo interface was created correctly.
  EXPECT_TRUE(interfaces_ptr->occupancy_trigger_handler_request.is_valid());
  EXPECT_EQ(fake_rtanalytics_->GetMostRecentOutputStreamName(),
            "fake_stream_name");

  OccupancyTriggerHandlerImpl occupancy_trigger_handler_impl(
      std::move(interfaces_ptr->occupancy_trigger_handler_request));
  base::RunLoop().RunUntilIdle();

  OccupancyTrigger occupancy_trigger;
  occupancy_trigger.set_trigger(true);
  output_manager.HandleOccupancyTrigger(
      Serialized<OccupancyTrigger>(occupancy_trigger).GetBytes());
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(occupancy_trigger_handler_impl.occupancy_trigger_.trigger(), true);
}

TEST_F(OutputManagerTest, AppearancesOutputManagerTest) {
  PerceptionInterfaces perception_interfaces;
  PerceptionInterface* interface = perception_interfaces.add_interface();
  interface->set_interface_type(PerceptionInterfaceType::INTERFACE_APPEARANCES);
  PipelineOutput* output = interface->add_output();
  output->set_output_type(PipelineOutputType::OUTPUT_APPEARANCES);
  output->set_stream_name("fake_stream_name");

  chromeos::media_perception::mojom::PerceptionInterfacesPtr interfaces_ptr =
      chromeos::media_perception::mojom::PerceptionInterfaces::New();

  OutputManager output_manager("fake_presence_perception_configuration",
                               rtanalytics_, perception_interfaces,
                               &interfaces_ptr);

  EXPECT_TRUE(interfaces_ptr->appearances_handler_request.is_valid());
  EXPECT_EQ(fake_rtanalytics_->GetMostRecentOutputStreamName(),
            "fake_stream_name");

  AppearancesHandlerImpl appearances_handler_impl(
      std::move(interfaces_ptr->appearances_handler_request));
  base::RunLoop().RunUntilIdle();

  std::vector<uint8_t> bytes{0, 1, 2, 3, 1, 2, 3, 2, 1};

  output_manager.HandleAppearances(bytes);
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(appearances_handler_impl.appearances_.size(), bytes.size())
      << "Vectors are of unequal length.";

  for (int i = 0; i < bytes.size(); ++i) {
    EXPECT_EQ(appearances_handler_impl.appearances_[i], bytes[i])
        << "Bytes and Output Appearances Vector differ at index " << i;
  }
}

TEST_F(OutputManagerTest, OneTouchAutozoomOutputManagerTest) {
  PerceptionInterfaces perception_interfaces;
  PerceptionInterface* interface = perception_interfaces.add_interface();
  interface->set_interface_type(
      PerceptionInterfaceType::INTERFACE_ONE_TOUCH_AUTOZOOM);
  PipelineOutput* output = interface->add_output();
  output->set_output_type(PipelineOutputType::OUTPUT_SMART_FRAMING);
  output->set_stream_name("fake_stream_name");

  chromeos::media_perception::mojom::PerceptionInterfacesPtr interfaces_ptr =
      chromeos::media_perception::mojom::PerceptionInterfaces::New();

  OutputManager output_manager("fake_one_touch_autozoom_configuration",
                               rtanalytics_, perception_interfaces,
                               &interfaces_ptr);

  EXPECT_TRUE(interfaces_ptr->one_touch_autozoom_handler_request.is_valid());
  EXPECT_EQ(fake_rtanalytics_->GetMostRecentOutputStreamName(),
            "fake_stream_name");

  OneTouchAutozoomHandlerImpl one_touch_autozoom_handler_impl(
      std::move(interfaces_ptr->one_touch_autozoom_handler_request));
  base::RunLoop().RunUntilIdle();

  std::vector<uint8_t> bytes{0, 1, 2, 3, 1, 2, 3, 2, 1};

  output_manager.HandleSmartFraming(bytes);
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(one_touch_autozoom_handler_impl.smart_framing_.size(), bytes.size())
      << "Vectors are of unequal length.";

  for (int i = 0; i < bytes.size(); ++i) {
    EXPECT_EQ(one_touch_autozoom_handler_impl.smart_framing_[i], bytes[i])
        << "Bytes and Output Appearances Vector differ at index " << i;
  }
}

TEST_F(OutputManagerTest, SoftwareAutozoomOutputManagerTest) {
  PerceptionInterfaces perception_interfaces;
  PerceptionInterface* interface = perception_interfaces.add_interface();
  interface->set_interface_type(
      PerceptionInterfaceType::INTERFACE_SOFTWARE_AUTOZOOM);
  PipelineOutput* output = interface->add_output();
  output->set_output_type(PipelineOutputType::OUTPUT_SMART_FRAMING);
  output->set_stream_name("fake_stream_name");

  chromeos::media_perception::mojom::PerceptionInterfacesPtr interfaces_ptr =
      chromeos::media_perception::mojom::PerceptionInterfaces::New();

  OutputManager output_manager("fake_software_autozoom_configuration",
                               rtanalytics_, perception_interfaces,
                               &interfaces_ptr);

  EXPECT_TRUE(interfaces_ptr->software_autozoom_handler_request.is_valid());
  EXPECT_EQ(fake_rtanalytics_->GetMostRecentOutputStreamName(),
            "fake_stream_name");

  SoftwareAutozoomHandlerImpl software_autozoom_handler_impl(
      std::move(interfaces_ptr->software_autozoom_handler_request));
  base::RunLoop().RunUntilIdle();

  std::vector<uint8_t> bytes{0, 1, 2, 3, 1, 2, 3, 2, 1};

  output_manager.HandleSmartFraming(bytes);
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(software_autozoom_handler_impl.smart_framing_.size(), bytes.size())
      << "Vectors are of unequal length.";

  for (int i = 0; i < bytes.size(); ++i) {
    EXPECT_EQ(software_autozoom_handler_impl.smart_framing_[i], bytes[i])
        << "Bytes and Output Appearances Vector differ at index " << i;
  }
}

}  // namespace
}  // namespace mri
