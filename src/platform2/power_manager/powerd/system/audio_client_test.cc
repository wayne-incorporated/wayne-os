// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/audio_client.h"

#include <memory>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "power_manager/powerd/system/audio_observer.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {
namespace {

// Trivial implementation of AudioObserver for unit tests.
class TestObserver : public AudioObserver {
 public:
  explicit TestObserver(AudioClient* client) : client_(client) {
    client_->AddObserver(this);
  }
  TestObserver(const TestObserver&) = delete;
  TestObserver& operator=(const TestObserver&) = delete;

  ~TestObserver() override { client_->RemoveObserver(this); }

  bool audio_active() const { return audio_active_; }
  int num_changes() const { return num_changes_; }

  // AudioObserver:
  void OnAudioStateChange(bool active) override {
    audio_active_ = active;
    num_changes_++;
  }

 private:
  AudioClient* client_;  // Not owned.

  bool audio_active_ = false;
  int num_changes_ = 0;
};

}  // namespace

class AudioClientTest : public TestEnvironment {
 public:
  AudioClientTest() {
    cras_proxy_ = dbus_wrapper_.GetObjectProxy(cras::kCrasServiceName,
                                               cras::kCrasServicePath);
    dbus_wrapper_.SetMethodCallback(base::BindRepeating(
        &AudioClientTest::HandleMethodCall, base::Unretained(this)));
    CHECK(run_dir_.CreateUniqueTempDir());
    CHECK(run_dir_.IsValid());
  }
  AudioClientTest(const AudioClientTest&) = delete;
  AudioClientTest& operator=(const AudioClientTest&) = delete;

  ~AudioClientTest() override = default;

  void Init() { audio_client_.Init(&dbus_wrapper_, run_dir_.GetPath()); }

 protected:
  DBusWrapperStub dbus_wrapper_;
  dbus::ObjectProxy* cras_proxy_ = nullptr;
  AudioClient audio_client_;
  // Run directory passed to |audio_client_|.
  base::ScopedTempDir run_dir_;

  // Number of output streams to report from GetNumberOfActiveOutputStreams.
  int num_output_streams_ = 0;

  // State to return from IsAudioOutputActive.
  bool output_active_ = false;

  // Audio nodes to be returned by GetNodes.
  struct Node {
    std::string type;
    bool active = false;
  };
  std::vector<Node> nodes_;

  // Most recent state set via SetSuspendAudio.
  bool audio_suspended_ = false;

 private:
  // DBusWrapperStub::MethodCallback implementation used to handle D-Bus calls
  // from |audio_client_|.
  std::unique_ptr<dbus::Response> HandleMethodCall(
      dbus::ObjectProxy* proxy, dbus::MethodCall* method_call) {
    if (proxy != cras_proxy_) {
      ADD_FAILURE() << "Unhandled method call to proxy " << proxy;
      return nullptr;
    }
    if (method_call->GetInterface() != cras::kCrasControlInterface) {
      ADD_FAILURE() << "Unhandled method call to interface "
                    << method_call->GetInterface();
      return nullptr;
    }

    std::unique_ptr<dbus::Response> response =
        dbus::Response::FromMethodCall(method_call);
    const std::string member = method_call->GetMember();
    if (member == cras::kGetNodes) {
      WriteNodes(response.get());
    } else if (member == cras::kGetNumberOfActiveOutputStreams) {
      dbus::MessageWriter(response.get()).AppendInt32(num_output_streams_);
    } else if (member == cras::kIsAudioOutputActive) {
      dbus::MessageWriter(response.get()).AppendInt32(output_active_);
    } else if (member == cras::kSetSuspendAudio) {
      if (!dbus::MessageReader(method_call).PopBool(&audio_suspended_))
        ADD_FAILURE() << "Couldn't read " << cras::kSetSuspendAudio << " arg";
    } else {
      ADD_FAILURE() << "Unhandled method call to member " << member;
      return nullptr;
    }
    return response;
  }

  // Helper method for HandleMethodCall() that writes |nodes_| to |response|
  // as an array of dicts mapping from string to variant.
  void WriteNodes(dbus::Response* response) {
    dbus::MessageWriter top_writer(response);
    for (const Node& node : nodes_) {
      // For each node, append a dict to the array.
      dbus::MessageWriter node_writer(nullptr);
      top_writer.OpenArray("{sv}", &node_writer);

      // Write the node type.
      dbus::MessageWriter type_writer(nullptr);
      node_writer.OpenDictEntry(&type_writer);
      type_writer.AppendString(AudioClient::kTypeKey);
      type_writer.AppendVariantOfString(node.type);
      node_writer.CloseContainer(&type_writer);

      // Write the node's active state.
      dbus::MessageWriter active_writer(nullptr);
      node_writer.OpenDictEntry(&active_writer);
      active_writer.AppendString(AudioClient::kActiveKey);
      active_writer.AppendVariantOfBool(node.active);
      node_writer.CloseContainer(&active_writer);

      // Close the node dict.
      top_writer.CloseContainer(&node_writer);
    }
  }
};

TEST_F(AudioClientTest, AudioState) {
  Init();

  // CRAS should be queried when it first becomes available.
  TestObserver observer(&audio_client_);
  num_output_streams_ = 1;
  output_active_ = true;
  dbus_wrapper_.NotifyServiceAvailable(cras_proxy_, true);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(observer.audio_active());
  EXPECT_EQ(1, observer.num_changes());

  // The observer shouldn't be notified if the stream count just increases.
  num_output_streams_ = 2;
  dbus::Signal stream_signal(cras::kCrasControlInterface,
                             cras::kNumberOfActiveStreamsChanged);
  dbus_wrapper_.EmitRegisteredSignal(cras_proxy_, &stream_signal);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(observer.audio_active());
  EXPECT_EQ(1, observer.num_changes());

  // It should hear about audio stopping entirely, though.
  num_output_streams_ = 0;
  dbus_wrapper_.EmitRegisteredSignal(cras_proxy_, &stream_signal);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(observer.audio_active());
  EXPECT_EQ(2, observer.num_changes());

  // The stream count should be requeried if CRAS restarts, too.
  num_output_streams_ = 1;
  dbus_wrapper_.NotifyNameOwnerChanged(cras::kCrasServiceName, "", ":0");
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(observer.audio_active());
  EXPECT_EQ(3, observer.num_changes());

  // If a stream is held open but nothing is being written to it, the observer
  // should be told that activity stopped.
  dbus::Signal active_signal(cras::kCrasControlInterface,
                             cras::kAudioOutputActiveStateChanged);
  dbus::MessageWriter(&active_signal).AppendBool(false);
  dbus_wrapper_.EmitRegisteredSignal(cras_proxy_, &active_signal);
  EXPECT_FALSE(observer.audio_active());
  EXPECT_EQ(4, observer.num_changes());
}

TEST_F(AudioClientTest, GetNodes) {
  Init();

  // With no connected nodes, nothing should be reported.
  dbus_wrapper_.NotifyNameOwnerChanged(cras::kCrasServiceName, "", ":0");
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(audio_client_.GetHeadphoneJackPlugged());
  EXPECT_FALSE(audio_client_.GetHdmiActive());

  // Ditto for a node of an unknown type.
  nodes_.push_back(Node{"FOO", true});
  dbus::Signal nodes_changed_signal(cras::kCrasControlInterface,
                                    cras::kNodesChanged);
  dbus_wrapper_.EmitRegisteredSignal(cras_proxy_, &nodes_changed_signal);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(audio_client_.GetHeadphoneJackPlugged());
  EXPECT_FALSE(audio_client_.GetHdmiActive());

  // After connecting headphones, they should be reported (even if inactive).
  nodes_.clear();
  nodes_.push_back(Node{AudioClient::kHeadphoneNodeType, false});
  dbus_wrapper_.EmitRegisteredSignal(cras_proxy_, &nodes_changed_signal);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(audio_client_.GetHeadphoneJackPlugged());
  EXPECT_FALSE(audio_client_.GetHdmiActive());

  // An inactive HDMI node shouldn't be reported.
  nodes_[0].active = true;
  nodes_.push_back(Node{AudioClient::kHdmiNodeType, false});
  dbus_wrapper_.EmitRegisteredSignal(cras_proxy_, &nodes_changed_signal);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(audio_client_.GetHeadphoneJackPlugged());
  EXPECT_FALSE(audio_client_.GetHdmiActive());

  // Once the HDMI node becomes active, it should be reported.
  nodes_[0].active = false;
  nodes_[1].active = true;
  dbus::Signal active_node_signal(cras::kCrasControlInterface,
                                  cras::kActiveOutputNodeChanged);
  dbus_wrapper_.EmitRegisteredSignal(cras_proxy_, &active_node_signal);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(audio_client_.GetHeadphoneJackPlugged());
  EXPECT_TRUE(audio_client_.GetHdmiActive());
}

TEST_F(AudioClientTest, SuspendAudio) {
  Init();

  auto audio_suspended_path =
      run_dir_.GetPath().Append(AudioClient::kAudioSuspendedFile);
  EXPECT_FALSE(audio_suspended_);
  EXPECT_FALSE(base::PathExists(audio_suspended_path));
  audio_client_.SetSuspended(true);
  EXPECT_TRUE(audio_suspended_);
  EXPECT_TRUE(base::PathExists(audio_suspended_path));
  audio_client_.SetSuspended(false);
  EXPECT_FALSE(audio_suspended_);
  EXPECT_FALSE(base::PathExists(audio_suspended_path));
}

TEST_F(AudioClientTest, PowerdCrashAfterAudioSuspended) {
  // Create |kAudioSuspendedFile| file in the |run_dir| which indicates the
  // previous run of powerd crashed after suspending audio.
  auto audio_suspended_path =
      run_dir_.GetPath().Append(AudioClient::kAudioSuspendedFile);
  ASSERT_EQ(base::WriteFile(audio_suspended_path, nullptr, 0), 0);
  audio_suspended_ = true;
  // audio_client_ Init() should un-suspend audio if it is suspended.
  Init();
  EXPECT_FALSE(audio_suspended_);
}

}  // namespace power_manager::system
