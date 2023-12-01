// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <memory>
#include <utility>

#include <base/dcheck_is_on.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/strings/strcat.h>
#include <base/task/single_thread_task_runner.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <featured/proto_bindings/featured.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "featured/feature_library.h"

namespace {

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

constexpr char kFeatureLibInterface[] = "org.chromium.feature_lib";
constexpr char kFeatureLibPath[] = "/org/chromium/feature_lib";
constexpr char kRefetchSignal[] = "RefetchFeatureState";

}  // namespace

namespace feature {

class FeatureLibraryTest : public testing::Test {
 protected:
  FeatureLibraryTest()
      : mock_bus_(new dbus::MockBus{dbus::Bus::Options{}}),
        mock_chrome_proxy_(new dbus::MockObjectProxy(
            mock_bus_.get(),
            chromeos::kChromeFeaturesServiceName,
            dbus::ObjectPath(chromeos::kChromeFeaturesServicePath))),
        mock_feature_proxy_(
            new dbus::MockObjectProxy(mock_bus_.get(),
                                      kFeatureLibInterface,
                                      dbus::ObjectPath(kFeatureLibPath))) {
    EXPECT_TRUE(dir_.CreateUniqueTempDir());
    active_trials_dir_ = dir_.GetPath().Append("active_trials");
    EXPECT_TRUE(base::CreateDirectory(active_trials_dir_));
  }

  void SetUp() override {
    PlatformFeatures::InitializeForTesting(mock_bus_, mock_chrome_proxy_.get(),
                                           mock_feature_proxy_.get());
    features_ = PlatformFeatures::Get();
    features_->SetActiveTrialFileDirectoryForTesting(active_trials_dir_);
  }

  void TearDown() override { PlatformFeatures::ShutdownForTesting(); }

  std::unique_ptr<dbus::Response> CreateIsEnabledResponse(
      dbus::MethodCall* call, bool enabled) {
    if (call->GetInterface() == "org.chromium.ChromeFeaturesServiceInterface" &&
        call->GetMember() == "IsFeatureEnabled") {
      std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
      dbus::MessageWriter writer(response.get());
      writer.AppendBool(enabled);
      return response;
    }
    LOG(ERROR) << "Unexpected method call " << call->ToString();
    return nullptr;
  }

  std::unique_ptr<dbus::Response> CreateGetParamsResponse(
      dbus::MethodCall* call,
      std::map<std::string, std::map<std::string, std::string>> params_map,
      std::map<std::string, bool> enabled_map) {
    if (call->GetInterface() == "org.chromium.ChromeFeaturesServiceInterface" &&
        call->GetMember() == "GetFeatureParams") {
      dbus::MessageReader reader(call);
      dbus::MessageReader array_reader(nullptr);
      if (!reader.PopArray(&array_reader)) {
        LOG(ERROR) << "Failed to read array of feature names.";
        return nullptr;
      }
      std::vector<std::string> input_features;
      while (array_reader.HasMoreData()) {
        std::string feature_name;
        if (!array_reader.PopString(&feature_name)) {
          LOG(ERROR) << "Failed to pop feature_name from array.";
          return nullptr;
        }
        input_features.push_back(feature_name);
      }

      std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
      dbus::MessageWriter writer(response.get());

      // Copied from chrome_features_service_provider.cc.
      dbus::MessageWriter array_writer(nullptr);
      // A map from feature name to:
      // * two booleans:
      //   * Whether to use the override (or the default),
      //   * What the override state is (only valid if we should use the
      //     override value).
      // * Another map, from parameter name to value.
      writer.OpenArray("{s(bba{ss})}", &array_writer);
      for (const auto& feature_name : input_features) {
        dbus::MessageWriter feature_dict_writer(nullptr);
        array_writer.OpenDictEntry(&feature_dict_writer);
        feature_dict_writer.AppendString(feature_name);
        dbus::MessageWriter struct_writer(nullptr);
        feature_dict_writer.OpenStruct(&struct_writer);

        if (enabled_map.find(feature_name) != enabled_map.end()) {
          struct_writer.AppendBool(true);  // Use override
          struct_writer.AppendBool(enabled_map[feature_name]);
        } else {
          struct_writer.AppendBool(false);  // Ignore override
          struct_writer.AppendBool(false);  // Arbitrary choice
        }

        dbus::MessageWriter sub_array_writer(nullptr);
        struct_writer.OpenArray("{ss}", &sub_array_writer);
        if (params_map.find(feature_name) != params_map.end()) {
          const auto& submap = params_map[feature_name];
          for (const auto& [key, value] : submap) {
            dbus::MessageWriter dict_writer(nullptr);
            sub_array_writer.OpenDictEntry(&dict_writer);
            dict_writer.AppendString(key);
            dict_writer.AppendString(value);
            sub_array_writer.CloseContainer(&dict_writer);
          }
        }
        struct_writer.CloseContainer(&sub_array_writer);
        feature_dict_writer.CloseContainer(&struct_writer);
        array_writer.CloseContainer(&feature_dict_writer);
      }
      writer.CloseContainer(&array_writer);

      return response;
    }
    LOG(ERROR) << "Unexpected method call " << call->ToString();
    return nullptr;
  }

  base::test::SingleThreadTaskEnvironment task_environment_;
  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> mock_chrome_proxy_;
  scoped_refptr<dbus::MockObjectProxy> mock_feature_proxy_;
  PlatformFeatures* features_;
  std::unique_ptr<base::RunLoop> run_loop_;
  base::FilePath active_trials_dir_;

 private:
  base::ScopedTempDir dir_;
};

// Parameterized tests, with a boolean indicating whether the feature should be
// enabled.
class FeatureLibraryParameterizedTest
    : public FeatureLibraryTest,
      public ::testing::WithParamInterface<bool> {};

INSTANTIATE_TEST_SUITE_P(FeatureLibraryParameterizedTest,
                         FeatureLibraryParameterizedTest,
                         testing::Values(true, false));

TEST_P(FeatureLibraryParameterizedTest, IsEnabled_Success) {
  bool enabled = GetParam();

  EXPECT_CALL(*mock_chrome_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(
          Invoke([](dbus::MockObjectProxy::WaitForServiceToBeAvailableCallback*
                        callback) { std::move(*callback).Run(true); }));

  EXPECT_CALL(*mock_chrome_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .WillOnce(Invoke(
          [this, enabled](dbus::MethodCall* call, int timeout_ms,
                          dbus::MockObjectProxy::ResponseCallback* callback) {
            std::unique_ptr<dbus::Response> resp =
                CreateIsEnabledResponse(call, enabled);
            std::move(*callback).Run(resp.get());
          }));

  run_loop_ = std::make_unique<base::RunLoop>();

  VariationsFeature f{"Feature", FEATURE_DISABLED_BY_DEFAULT};
  features_->IsEnabled(f,
                       base::BindLambdaForTesting([this, enabled](bool actual) {
                         EXPECT_EQ(enabled, actual);
                         run_loop_->Quit();
                       }));

  run_loop_->Run();
}

TEST_P(FeatureLibraryParameterizedTest, IsEnabled_Failure_WaitForService) {
  EXPECT_CALL(*mock_chrome_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(
          Invoke([](dbus::MockObjectProxy::WaitForServiceToBeAvailableCallback*
                        callback) { std::move(*callback).Run(false); }));

  EXPECT_CALL(*mock_chrome_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .Times(0);

  run_loop_ = std::make_unique<base::RunLoop>();

  bool enabled = GetParam();
  FeatureState feature_state =
      GetParam() ? FEATURE_ENABLED_BY_DEFAULT : FEATURE_DISABLED_BY_DEFAULT;
  VariationsFeature f{"Feature", feature_state};

  features_->IsEnabled(f,
                       base::BindLambdaForTesting([this, enabled](bool actual) {
                         EXPECT_EQ(enabled, actual);
                         run_loop_->Quit();
                       }));
  run_loop_->Run();
}

TEST_P(FeatureLibraryParameterizedTest, IsEnabled_Failure_NullResponse) {
  EXPECT_CALL(*mock_chrome_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(
          Invoke([](dbus::MockObjectProxy::WaitForServiceToBeAvailableCallback*
                        callback) { std::move(*callback).Run(true); }));

  EXPECT_CALL(*mock_chrome_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .WillOnce(Invoke([](dbus::MethodCall* call, int timeout_ms,
                          dbus::MockObjectProxy::ResponseCallback* callback) {
        std::move(*callback).Run(nullptr);
      }));

  run_loop_ = std::make_unique<base::RunLoop>();

  bool enabled = GetParam();
  FeatureState feature_state =
      GetParam() ? FEATURE_ENABLED_BY_DEFAULT : FEATURE_DISABLED_BY_DEFAULT;
  VariationsFeature f{"Feature", feature_state};

  features_->IsEnabled(f,
                       base::BindLambdaForTesting([this, enabled](bool actual) {
                         EXPECT_EQ(enabled, actual);
                         run_loop_->Quit();
                       }));
  run_loop_->Run();
}

TEST_P(FeatureLibraryParameterizedTest, IsEnabled_Failure_EmptyResponse) {
  EXPECT_CALL(*mock_chrome_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(
          Invoke([](dbus::MockObjectProxy::WaitForServiceToBeAvailableCallback*
                        callback) { std::move(*callback).Run(true); }));

  std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
  EXPECT_CALL(*mock_chrome_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .WillOnce(Invoke(
          [&response](dbus::MethodCall* call, int timeout_ms,
                      dbus::MockObjectProxy::ResponseCallback* callback) {
            std::move(*callback).Run(response.get());
          }));

  run_loop_ = std::make_unique<base::RunLoop>();

  bool enabled = GetParam();
  FeatureState feature_state =
      GetParam() ? FEATURE_ENABLED_BY_DEFAULT : FEATURE_DISABLED_BY_DEFAULT;
  VariationsFeature f{"Feature", feature_state};

  features_->IsEnabled(f,
                       base::BindLambdaForTesting([this, enabled](bool actual) {
                         EXPECT_EQ(enabled, actual);
                         run_loop_->Quit();
                       }));

  run_loop_->Run();
}

TEST_P(FeatureLibraryParameterizedTest, IsEnabledBlocking_Success) {
  bool enabled = GetParam();

  EXPECT_CALL(*mock_chrome_proxy_,
              CallMethodAndBlock(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(Invoke([this, enabled](dbus::MethodCall* call, int timeout_ms) {
        return CreateIsEnabledResponse(call, enabled);
      }));

  VariationsFeature f{"Feature", FEATURE_DISABLED_BY_DEFAULT};
  EXPECT_EQ(enabled, features_->IsEnabledBlocking(f));
}

TEST_P(FeatureLibraryParameterizedTest, IsEnabledBlocking_Failure_Null) {
  EXPECT_CALL(*mock_chrome_proxy_,
              CallMethodAndBlock(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(Invoke(
          [](dbus::MethodCall* call, int timeout_ms) { return nullptr; }));

  bool enabled = GetParam();
  FeatureState feature_state =
      GetParam() ? FEATURE_ENABLED_BY_DEFAULT : FEATURE_DISABLED_BY_DEFAULT;
  VariationsFeature f{"Feature", feature_state};

  EXPECT_EQ(enabled, features_->IsEnabledBlocking(f));
}

TEST_P(FeatureLibraryParameterizedTest, IsEnabledBlocking_Failure_Empty) {
  EXPECT_CALL(*mock_chrome_proxy_,
              CallMethodAndBlock(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(Invoke([](dbus::MethodCall* call, int timeout_ms) {
        return dbus::Response::CreateEmpty();
      }));

  bool enabled = GetParam();
  FeatureState feature_state =
      GetParam() ? FEATURE_ENABLED_BY_DEFAULT : FEATURE_DISABLED_BY_DEFAULT;
  VariationsFeature f{"Feature", feature_state};

  EXPECT_EQ(enabled, features_->IsEnabledBlocking(f));
}

TEST_P(FeatureLibraryParameterizedTest, IsEnabledBlockingWithTimeout_Success) {
  int timeout = 100;
  bool enabled = GetParam();

  EXPECT_CALL(*mock_chrome_proxy_, CallMethodAndBlock(_, timeout))
      .WillOnce(Invoke([this, enabled](dbus::MethodCall* call, int timeout_ms) {
        return CreateIsEnabledResponse(call, enabled);
      }));

  VariationsFeature f{"Feature", FEATURE_DISABLED_BY_DEFAULT};
  EXPECT_EQ(enabled, features_->IsEnabledBlockingWithTimeout(f, timeout));
}

TEST_P(FeatureLibraryParameterizedTest,
       IsEnabledBlockingWithTimeout_Failure_Null) {
  int timeout = 100;
  EXPECT_CALL(*mock_chrome_proxy_, CallMethodAndBlock(_, timeout))
      .WillOnce(Invoke(
          [](dbus::MethodCall* call, int timeout_ms) { return nullptr; }));

  bool enabled = GetParam();
  FeatureState feature_state =
      GetParam() ? FEATURE_ENABLED_BY_DEFAULT : FEATURE_DISABLED_BY_DEFAULT;
  VariationsFeature f{"Feature", feature_state};

  EXPECT_EQ(enabled, features_->IsEnabledBlockingWithTimeout(f, timeout));
}

TEST_P(FeatureLibraryParameterizedTest,
       IsEnabledBlockingWithTimeout_Failure_Empty) {
  int timeout = 100;
  EXPECT_CALL(*mock_chrome_proxy_, CallMethodAndBlock(_, timeout))
      .WillOnce(Invoke([](dbus::MethodCall* call, int timeout_ms) {
        return dbus::Response::CreateEmpty();
      }));

  bool enabled = GetParam();
  FeatureState feature_state =
      GetParam() ? FEATURE_ENABLED_BY_DEFAULT : FEATURE_DISABLED_BY_DEFAULT;
  VariationsFeature f{"Feature", feature_state};

  EXPECT_EQ(enabled, features_->IsEnabledBlockingWithTimeout(f, timeout));
}

TEST_F(FeatureLibraryTest, GetParamsAndEnabled_Success) {
  // Will be enabled with params.
  VariationsFeature f1{"Feature1", FEATURE_DISABLED_BY_DEFAULT};
  // Will be explicitly disabled (and hence no params).
  VariationsFeature f2{"Feature2", FEATURE_DISABLED_BY_DEFAULT};
  // Will be default state (and hence no params).
  VariationsFeature f3{"Feature3", FEATURE_DISABLED_BY_DEFAULT};
  // Will be explicitly disabled (and hence no params).
  VariationsFeature f4{"Feature4", FEATURE_ENABLED_BY_DEFAULT};
  // Will be enabled with *no* params
  VariationsFeature f5{"Feature5", FEATURE_DISABLED_BY_DEFAULT};
  // Will be enabled by default with *no* params
  VariationsFeature f6{"Feature6", FEATURE_ENABLED_BY_DEFAULT};

  std::map<std::string, std::map<std::string, std::string>> params_map{
      {f1.name, {{"key", "value"}, {"anotherkey", "anothervalue"}}},
  };
  std::map<std::string, bool> enabled_map{
      {f1.name, true},
      {f2.name, false},
      // f3 is default
      {f4.name, false},
      {f5.name, true},
      // f6 is default
  };

  EXPECT_CALL(*mock_chrome_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(
          Invoke([](dbus::MockObjectProxy::WaitForServiceToBeAvailableCallback*
                        callback) { std::move(*callback).Run(true); }));

  EXPECT_CALL(*mock_chrome_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .WillOnce(Invoke([this, enabled_map, params_map](
                           dbus::MethodCall* call, int timeout_ms,
                           dbus::MockObjectProxy::ResponseCallback* callback) {
        std::unique_ptr<dbus::Response> resp =
            CreateGetParamsResponse(call, params_map, enabled_map);
        std::move(*callback).Run(resp.get());
      }));

  run_loop_ = std::make_unique<base::RunLoop>();

  PlatformFeaturesInterface::ParamsResult expected{
      {
          f1.name,
          {
              .enabled = true,
              .params = params_map[f1.name],
          },
      },
      {
          f2.name,
          {
              .enabled = false,
          },
      },
      {
          f3.name,
          {
              .enabled = false,
          },
      },
      {
          f4.name,
          {
              .enabled = false,
          },
      },
      {
          f5.name,
          {
              .enabled = true,
          },
      },
      {
          f6.name,
          {
              .enabled = true,
          },
      }};

  features_->GetParamsAndEnabled(
      {&f1, &f2, &f3, &f4, &f5, &f6},
      base::BindLambdaForTesting(
          [this, expected](PlatformFeaturesInterface::ParamsResult actual) {
            EXPECT_EQ(actual.size(), expected.size());
            for (const auto& [name, entry] : actual) {
              auto it = expected.find(name);
              ASSERT_NE(it, expected.end()) << name;
              EXPECT_EQ(entry.enabled, it->second.enabled) << name;
              EXPECT_EQ(entry.params, it->second.params) << name;
            }
            run_loop_->Quit();
          }));

  run_loop_->Run();
}

TEST_F(FeatureLibraryTest, GetParamsAndEnabled_Failure_WaitForService) {
  EXPECT_CALL(*mock_chrome_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(
          Invoke([](dbus::MockObjectProxy::WaitForServiceToBeAvailableCallback*
                        callback) { std::move(*callback).Run(false); }));

  EXPECT_CALL(*mock_chrome_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .Times(0);

  run_loop_ = std::make_unique<base::RunLoop>();

  VariationsFeature f1{"Feature1", FEATURE_ENABLED_BY_DEFAULT};
  VariationsFeature f2{"Feature2", FEATURE_DISABLED_BY_DEFAULT};

  PlatformFeaturesInterface::ParamsResult expected{{
                                                       f1.name,
                                                       {
                                                           .enabled = true,
                                                       },
                                                   },
                                                   {
                                                       f2.name,
                                                       {
                                                           .enabled = false,
                                                       },
                                                   }};

  features_->GetParamsAndEnabled(
      {&f1, &f2},
      base::BindLambdaForTesting(
          [this, expected](PlatformFeaturesInterface::ParamsResult actual) {
            EXPECT_EQ(actual.size(), expected.size());
            for (const auto& [name, entry] : actual) {
              auto it = expected.find(name);
              ASSERT_NE(it, expected.end()) << name;
              EXPECT_EQ(entry.enabled, it->second.enabled) << name;
              EXPECT_EQ(entry.params, it->second.params) << name;
            }
            run_loop_->Quit();
          }));
  run_loop_->Run();
}

TEST_F(FeatureLibraryTest, GetParamsAndEnabled_Failure_Null) {
  EXPECT_CALL(*mock_chrome_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(
          Invoke([](dbus::MockObjectProxy::WaitForServiceToBeAvailableCallback*
                        callback) { std::move(*callback).Run(true); }));

  EXPECT_CALL(*mock_chrome_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .WillOnce(Invoke([](dbus::MethodCall* call, int timeout_ms,
                          dbus::MockObjectProxy::ResponseCallback* callback) {
        std::move(*callback).Run(nullptr);
      }));

  run_loop_ = std::make_unique<base::RunLoop>();

  VariationsFeature f1{"Feature1", FEATURE_ENABLED_BY_DEFAULT};
  VariationsFeature f2{"Feature2", FEATURE_DISABLED_BY_DEFAULT};

  PlatformFeaturesInterface::ParamsResult expected{{
                                                       f1.name,
                                                       {
                                                           .enabled = true,
                                                       },
                                                   },
                                                   {
                                                       f2.name,
                                                       {
                                                           .enabled = false,
                                                       },
                                                   }};

  features_->GetParamsAndEnabled(
      {&f1, &f2},
      base::BindLambdaForTesting(
          [this, expected](PlatformFeaturesInterface::ParamsResult actual) {
            EXPECT_EQ(actual.size(), expected.size());
            for (const auto& [name, entry] : actual) {
              auto it = expected.find(name);
              ASSERT_NE(it, expected.end()) << name;
              EXPECT_EQ(entry.enabled, it->second.enabled) << name;
              EXPECT_EQ(entry.params, it->second.params) << name;
            }
            run_loop_->Quit();
          }));
  run_loop_->Run();
}

TEST_F(FeatureLibraryTest, GetParamsAndEnabled_Failure_Empty) {
  EXPECT_CALL(*mock_chrome_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(
          Invoke([](dbus::MockObjectProxy::WaitForServiceToBeAvailableCallback*
                        callback) { std::move(*callback).Run(true); }));

  std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
  EXPECT_CALL(*mock_chrome_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .WillOnce(Invoke(
          [&response](dbus::MethodCall* call, int timeout_ms,
                      dbus::MockObjectProxy::ResponseCallback* callback) {
            std::move(*callback).Run(response.get());
          }));

  run_loop_ = std::make_unique<base::RunLoop>();

  VariationsFeature f1{"Feature1", FEATURE_ENABLED_BY_DEFAULT};
  VariationsFeature f2{"Feature2", FEATURE_DISABLED_BY_DEFAULT};

  PlatformFeaturesInterface::ParamsResult expected{{
                                                       f1.name,
                                                       {
                                                           .enabled = true,
                                                       },
                                                   },
                                                   {
                                                       f2.name,
                                                       {
                                                           .enabled = false,
                                                       },
                                                   }};

  features_->GetParamsAndEnabled(
      {&f1, &f2},
      base::BindLambdaForTesting(
          [this, expected](PlatformFeaturesInterface::ParamsResult actual) {
            EXPECT_EQ(actual.size(), expected.size());
            for (const auto& [name, entry] : actual) {
              auto it = expected.find(name);
              ASSERT_NE(it, expected.end()) << name;
              EXPECT_EQ(entry.enabled, it->second.enabled) << name;
              EXPECT_EQ(entry.params, it->second.params) << name;
            }
            run_loop_->Quit();
          }));
  run_loop_->Run();
}

// Invalid response should result in default values.
TEST_F(FeatureLibraryTest, GetParamsAndEnabled_Failure_Invalid) {
  EXPECT_CALL(*mock_chrome_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(
          Invoke([](dbus::MockObjectProxy::WaitForServiceToBeAvailableCallback*
                        callback) { std::move(*callback).Run(true); }));

  std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
  dbus::MessageWriter writer(response.get());
  writer.AppendBool(true);
  writer.AppendBool(true);
  EXPECT_CALL(*mock_chrome_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .WillOnce(Invoke(
          [&response](dbus::MethodCall* call, int timeout_ms,
                      dbus::MockObjectProxy::ResponseCallback* callback) {
            std::move(*callback).Run(response.get());
          }));

  run_loop_ = std::make_unique<base::RunLoop>();

  VariationsFeature f1{"Feature1", FEATURE_ENABLED_BY_DEFAULT};
  VariationsFeature f2{"Feature2", FEATURE_DISABLED_BY_DEFAULT};

  PlatformFeaturesInterface::ParamsResult expected{{
                                                       f1.name,
                                                       {
                                                           .enabled = true,
                                                       },
                                                   },
                                                   {
                                                       f2.name,
                                                       {
                                                           .enabled = false,
                                                       },
                                                   }};

  features_->GetParamsAndEnabled(
      {&f1, &f2},
      base::BindLambdaForTesting(
          [this, expected](PlatformFeaturesInterface::ParamsResult actual) {
            EXPECT_EQ(actual.size(), expected.size());
            for (const auto& [name, entry] : actual) {
              auto it = expected.find(name);
              ASSERT_NE(it, expected.end()) << name;
              EXPECT_EQ(entry.enabled, it->second.enabled) << name;
              EXPECT_EQ(entry.params, it->second.params) << name;
            }
            run_loop_->Quit();
          }));
  run_loop_->Run();
}

TEST_F(FeatureLibraryTest, GetParamsAndEnabledBlocking) {
  // Will be enabled with params.
  VariationsFeature f1{"Feature1", FEATURE_DISABLED_BY_DEFAULT};
  // Will be explicitly disabled (and hence no params).
  VariationsFeature f2{"Feature2", FEATURE_DISABLED_BY_DEFAULT};
  // Will be default state (and hence no params).
  VariationsFeature f3{"Feature3", FEATURE_DISABLED_BY_DEFAULT};
  // Will be explicitly disabled (and hence no params).
  VariationsFeature f4{"Feature4", FEATURE_ENABLED_BY_DEFAULT};
  // Will be enabled with *no* params
  VariationsFeature f5{"Feature5", FEATURE_DISABLED_BY_DEFAULT};
  // Will be enabled by default with *no* params
  VariationsFeature f6{"Feature6", FEATURE_ENABLED_BY_DEFAULT};

  std::map<std::string, std::map<std::string, std::string>> params_map{
      {f1.name, {{"key", "value"}, {"anotherkey", "anothervalue"}}},
  };
  std::map<std::string, bool> enabled_map{
      {f1.name, true},
      {f2.name, false},
      // f3 is default
      {f4.name, false},
      {f5.name, true},
      // f6 is default
  };

  EXPECT_CALL(*mock_chrome_proxy_,
              CallMethodAndBlock(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(Invoke([this, enabled_map, params_map](dbus::MethodCall* call,
                                                       int timeout_ms) {
        return CreateGetParamsResponse(call, params_map, enabled_map);
      }));

  PlatformFeaturesInterface::ParamsResult expected{
      {
          f1.name,
          {
              .enabled = true,
              .params = params_map[f1.name],
          },
      },
      {
          f2.name,
          {
              .enabled = false,
          },
      },
      {
          f3.name,
          {
              .enabled = false,
          },
      },
      {
          f4.name,
          {
              .enabled = false,
          },
      },
      {
          f5.name,
          {
              .enabled = true,
          },
      },
      {
          f6.name,
          {
              .enabled = true,
          },
      }};

  auto actual =
      features_->GetParamsAndEnabledBlocking({&f1, &f2, &f3, &f4, &f5, &f6});
  EXPECT_EQ(actual.size(), expected.size());
  for (const auto& [name, entry] : actual) {
    auto it = expected.find(name);
    ASSERT_NE(it, expected.end()) << name;
    EXPECT_EQ(entry.enabled, it->second.enabled) << name;
    EXPECT_EQ(entry.params, it->second.params) << name;
  }
}

TEST_F(FeatureLibraryTest, GetParamsAndEnabledBlocking_Failure_Null) {
  EXPECT_CALL(*mock_chrome_proxy_,
              CallMethodAndBlock(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(Invoke(
          [](dbus::MethodCall* call, int timeout_ms) { return nullptr; }));

  VariationsFeature f1{"Feature1", FEATURE_ENABLED_BY_DEFAULT};
  VariationsFeature f2{"Feature2", FEATURE_DISABLED_BY_DEFAULT};

  PlatformFeaturesInterface::ParamsResult expected{{
                                                       f1.name,
                                                       {
                                                           .enabled = true,
                                                       },
                                                   },
                                                   {
                                                       f2.name,
                                                       {
                                                           .enabled = false,
                                                       },
                                                   }};

  auto actual = features_->GetParamsAndEnabledBlocking({&f1, &f2});
  EXPECT_EQ(actual.size(), expected.size());
  for (const auto& [name, entry] : actual) {
    auto it = expected.find(name);
    ASSERT_NE(it, expected.end()) << name;
    EXPECT_EQ(entry.enabled, it->second.enabled) << name;
    EXPECT_EQ(entry.params, it->second.params) << name;
  }
}

TEST_F(FeatureLibraryTest, GetParamsAndEnabledBlocking_Failure_Empty) {
  EXPECT_CALL(*mock_chrome_proxy_,
              CallMethodAndBlock(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(Invoke([](dbus::MethodCall* call, int timeout_ms) {
        return dbus::Response::CreateEmpty();
      }));

  VariationsFeature f1{"Feature1", FEATURE_ENABLED_BY_DEFAULT};
  VariationsFeature f2{"Feature2", FEATURE_DISABLED_BY_DEFAULT};

  PlatformFeaturesInterface::ParamsResult expected{{
                                                       f1.name,
                                                       {
                                                           .enabled = true,
                                                       },
                                                   },
                                                   {
                                                       f2.name,
                                                       {
                                                           .enabled = false,
                                                       },
                                                   }};

  auto actual = features_->GetParamsAndEnabledBlocking({&f1, &f2});
  EXPECT_EQ(actual.size(), expected.size());
  for (const auto& [name, entry] : actual) {
    auto it = expected.find(name);
    ASSERT_NE(it, expected.end()) << name;
    EXPECT_EQ(entry.enabled, it->second.enabled) << name;
    EXPECT_EQ(entry.params, it->second.params) << name;
  }
}

// Invalid response should result in default values.
TEST_F(FeatureLibraryTest, GetParamsAndEnabledBlocking_Failure_Invalid) {
  EXPECT_CALL(*mock_chrome_proxy_,
              CallMethodAndBlock(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(Invoke([](dbus::MethodCall* call, int timeout_ms) {
        std::unique_ptr<dbus::Response> response =
            dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(response.get());
        writer.AppendBool(true);
        writer.AppendBool(true);
        return response;
      }));

  VariationsFeature f1{"Feature1", FEATURE_ENABLED_BY_DEFAULT};
  VariationsFeature f2{"Feature2", FEATURE_DISABLED_BY_DEFAULT};

  PlatformFeaturesInterface::ParamsResult expected{{
                                                       f1.name,
                                                       {
                                                           .enabled = true,
                                                       },
                                                   },
                                                   {
                                                       f2.name,
                                                       {
                                                           .enabled = false,
                                                       },
                                                   }};

  auto actual = features_->GetParamsAndEnabledBlocking({&f1, &f2});
  EXPECT_EQ(actual.size(), expected.size());
  for (const auto& [name, entry] : actual) {
    auto it = expected.find(name);
    ASSERT_NE(it, expected.end()) << name;
    EXPECT_EQ(entry.enabled, it->second.enabled) << name;
    EXPECT_EQ(entry.params, it->second.params) << name;
  }
}

TEST_F(FeatureLibraryTest, CheckFeatureIdentity) {
  VariationsFeature f1{"Feature", FEATURE_ENABLED_BY_DEFAULT};
  // A new, unseen feature should pass the check.
  EXPECT_TRUE(features_->CheckFeatureIdentity(f1));
  // As should a feature seen a second time.
  EXPECT_TRUE(features_->CheckFeatureIdentity(f1));

  VariationsFeature f2{"Feature", FEATURE_ENABLED_BY_DEFAULT};
  // A separate feature with the same name should fail.
  EXPECT_FALSE(features_->CheckFeatureIdentity(f2));

  VariationsFeature f3{"Feature3", FEATURE_ENABLED_BY_DEFAULT};
  // A distinct feature with a distinct name should pass.
  EXPECT_TRUE(features_->CheckFeatureIdentity(f3));
  EXPECT_TRUE(features_->CheckFeatureIdentity(f3));
}

// Test that registering the signal handler registers the right signal handler,
// and that success is appropriately reported.
TEST_F(FeatureLibraryTest, RegisterSignalHandler_Success) {
  EXPECT_CALL(*mock_feature_proxy_,
              DoConnectToSignal(kFeatureLibInterface, kRefetchSignal, _, _))
      .WillOnce([](const std::string& interface, const std::string& signal,
                   dbus::ObjectProxy::SignalCallback signal_cb,
                   dbus::ObjectProxy::OnConnectedCallback* on_connected) {
        std::move(*on_connected).Run(interface, signal, true);
      });

  bool ran = false;
  bool result = false;
  features_->ListenForRefetchNeeded(
      base::DoNothing(),
      base::BindLambdaForTesting([&ran, &result](bool success) {
        result = success;
        ran = true;
      }));
  EXPECT_TRUE(ran);
  EXPECT_TRUE(result);
}

// Test that registering the signal handler registers the right signal handler,
// and that failure is appropriately reported.
TEST_F(FeatureLibraryTest, RegisterSignalHandler_Failure) {
  EXPECT_CALL(*mock_feature_proxy_,
              DoConnectToSignal(kFeatureLibInterface, kRefetchSignal, _, _))
      .WillOnce([](const std::string& interface, const std::string& signal,
                   dbus::ObjectProxy::SignalCallback signal_cb,
                   dbus::ObjectProxy::OnConnectedCallback* on_connected) {
        std::move(*on_connected).Run(interface, signal, false);
      });

  bool ran = false;
  bool result = false;
  features_->ListenForRefetchNeeded(
      base::DoNothing(),
      base::BindLambdaForTesting([&ran, &result](bool success) {
        result = success;
        ran = true;
      }));
  EXPECT_TRUE(ran);
  EXPECT_FALSE(result);
}

// Test that an active trial file is written.
TEST_F(FeatureLibraryTest, RecordSingleActiveTrial) {
  featured::FeatureOverride trial;
  trial.set_trial_name("test_trial");
  trial.set_group_name("test_group");
  features_->RecordActiveTrial(trial);

  size_t num_found_files = 0;
  base::FileEnumerator e(active_trials_dir_, /*recursive=*/false,
                         base::FileEnumerator::FILES);
  for (base::FilePath file = e.Next(); !file.empty(); file = e.Next()) {
    EXPECT_EQ(file.BaseName(), base::FilePath("test_trial,test_group"));
    ++num_found_files;
  }

  EXPECT_EQ(num_found_files, 1);
}

// Test that multiple active feature files are written for non-duplicate
// features.
TEST_F(FeatureLibraryTest, RecordMultipleActiveTrials) {
  featured::FeatureOverride f1;
  f1.set_trial_name("test_trial_1");
  f1.set_group_name("test_group_1");
  features_->RecordActiveTrial(f1);

  featured::FeatureOverride f2;
  f2.set_trial_name("test_trial_2");
  f2.set_group_name("test_group_2");

  features_->RecordActiveTrial(f2);

  std::vector<base::FilePath> expected_files;
  expected_files.push_back(base::FilePath("test_trial_1,test_group_1"));
  expected_files.push_back(base::FilePath("test_trial_2,test_group_2"));

  size_t num_found_files = 0;
  base::FileEnumerator e(active_trials_dir_, /*recursive=*/false,
                         base::FileEnumerator::FILES);
  for (base::FilePath file = e.Next(); !file.empty(); file = e.Next()) {
    EXPECT_TRUE(base::Contains(expected_files, file.BaseName()));
    ++num_found_files;
  }

  EXPECT_EQ(num_found_files, expected_files.size());
}

// Test that only one active feature file is written when recording duplicate
// active features.
TEST_F(FeatureLibraryTest, RecordDuplicateActiveTrialOnlyOnce) {
  featured::FeatureOverride trial;
  trial.set_trial_name("test_trial");
  trial.set_group_name("test_group");

  features_->RecordActiveTrial(trial);
  features_->RecordActiveTrial(trial);

  size_t num_found_files = 0;
  base::FileEnumerator e(active_trials_dir_, /*recursive=*/false,
                         base::FileEnumerator::FILES);
  for (base::FilePath file = e.Next(); !file.empty(); file = e.Next()) {
    EXPECT_EQ(file.BaseName(), base::FilePath("test_trial,test_group"));
    ++num_found_files;
  }

  EXPECT_EQ(num_found_files, 1);
}

// Test that trial names with kTrialGroupSeparator get escaped.
TEST_F(FeatureLibraryTest, EscapeTrialNameWithSeparator) {
  featured::FeatureOverride trial;
  trial.set_trial_name("test_trial,");
  trial.set_group_name("test_group");

  features_->RecordActiveTrial(trial);

  size_t num_found_files = 0;
  base::FileEnumerator e(active_trials_dir_, /*recursive=*/false,
                         base::FileEnumerator::FILES);
  for (base::FilePath file = e.Next(); !file.empty(); file = e.Next()) {
    EXPECT_EQ(file.BaseName(), base::FilePath("test_trial%2C,test_group"));
    ++num_found_files;
  }

  EXPECT_EQ(num_found_files, 1);
}

// Test that trial names with forward slashes are escaped and created as files,
// not as subdirectories.
TEST_F(FeatureLibraryTest, EscapeTrialNameWithForwardSlash) {
  featured::FeatureOverride trial;
  trial.set_trial_name("test_trial/");
  trial.set_group_name("test_group");

  features_->RecordActiveTrial(trial);

  size_t num_found_files = 0;
  base::FileEnumerator e(active_trials_dir_, /*recursive=*/false,
                         base::FileEnumerator::FILES);
  for (base::FilePath file = e.Next(); !file.empty(); file = e.Next()) {
    EXPECT_EQ(file.BaseName(), base::FilePath("test_trial%2F,test_group"));
    ++num_found_files;
  }

  EXPECT_EQ(num_found_files, 1);
}

#if DCHECK_IS_ON()
using FeatureLibraryDeathTest = FeatureLibraryTest;
TEST_F(FeatureLibraryDeathTest, IsEnabledDistinctFeatureDefs) {
  EXPECT_CALL(*mock_chrome_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(
          Invoke([](dbus::MockObjectProxy::WaitForServiceToBeAvailableCallback*
                        callback) { std::move(*callback).Run(false); }));

  EXPECT_CALL(*mock_chrome_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .Times(0);

  run_loop_ = std::make_unique<base::RunLoop>();

  VariationsFeature f{"Feature", FEATURE_ENABLED_BY_DEFAULT};
  features_->IsEnabled(f, base::BindLambdaForTesting([this](bool enabled) {
                         EXPECT_TRUE(enabled);  // Default value
                         run_loop_->Quit();
                       }));
  run_loop_->Run();

  VariationsFeature f2{"Feature", FEATURE_ENABLED_BY_DEFAULT};
  EXPECT_DEATH(
      features_->IsEnabled(f2, base::BindLambdaForTesting([this](bool enabled) {
                             EXPECT_TRUE(enabled);  // Default value
                             run_loop_->Quit();
                           })),
      "Feature");
}

TEST_F(FeatureLibraryDeathTest, IsEnabledBlockingDistinctFeatureDefs) {
  EXPECT_CALL(*mock_chrome_proxy_,
              CallMethodAndBlock(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .Times(1);

  VariationsFeature f{"Feature", FEATURE_ENABLED_BY_DEFAULT};
  features_->IsEnabledBlocking(f);

  VariationsFeature f2{"Feature", FEATURE_ENABLED_BY_DEFAULT};
  EXPECT_DEATH(features_->IsEnabledBlocking(f2), "Feature");
}
#endif  // DCHECK_IS_ON()

}  // namespace feature
