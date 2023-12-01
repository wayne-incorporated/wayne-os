// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/scope_logger.h"

#include <base/functional/bind.h>
#include <base/memory/weak_ptr.h>

#include "shill/logging.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;

namespace shill {

class ScopeLoggerTest : public testing::Test {
 protected:
  ScopeLoggerTest() : logger_(ScopeLogger::GetInstance()) {}

  void TearDown() {
    logger_->set_verbose_level(0);
    logger_->DisableAllScopes();
  }

  ScopeLogger* logger_;
};

TEST_F(ScopeLoggerTest, DefaultConstruction) {
  for (int scope = 0; scope < ScopeLogger::kNumScopes; ++scope) {
    for (int verbose_level = 0; verbose_level < 5; ++verbose_level) {
      EXPECT_FALSE(ScopeLogger::IsLogEnabled(
          static_cast<ScopeLogger::Scope>(scope), verbose_level));
    }
  }
}

TEST_F(ScopeLoggerTest, GetAllScopeNames) {
  EXPECT_EQ(
      "bluetooth+"
      "cellular+"
      "connection+"
      "crypto+"
      "daemon+"
      "dbus+"
      "device+"
      "dhcp+"
      "dns+"
      "ethernet+"
      "http+"
      "inet+"
      "link+"
      "manager+"
      "metrics+"
      "modem+"
      "portal+"
      "power+"
      "ppp+"
      "profile+"
      "property+"
      "resolver+"
      "route+"
      "rtnl+"
      "service+"
      "storage+"
      "task+"
      "tc+"
      "vpn+"
      "wifi",
      logger_->GetAllScopeNames());
}

TEST_F(ScopeLoggerTest, GetEnabledScopeNames) {
  EXPECT_EQ("", logger_->GetEnabledScopeNames());

  logger_->SetScopeEnabled(ScopeLogger::kWiFi, true);
  EXPECT_EQ("wifi", logger_->GetEnabledScopeNames());

  logger_->SetScopeEnabled(ScopeLogger::kService, true);
  EXPECT_EQ("service+wifi", logger_->GetEnabledScopeNames());

  logger_->SetScopeEnabled(ScopeLogger::kVPN, true);
  EXPECT_EQ("service+vpn+wifi", logger_->GetEnabledScopeNames());

  logger_->SetScopeEnabled(ScopeLogger::kWiFi, false);
  EXPECT_EQ("service+vpn", logger_->GetEnabledScopeNames());
}

TEST_F(ScopeLoggerTest, EnableScopesByName) {
  logger_->EnableScopesByName("");
  EXPECT_EQ("", logger_->GetEnabledScopeNames());

  logger_->EnableScopesByName("+wifi");
  EXPECT_EQ("wifi", logger_->GetEnabledScopeNames());

  logger_->EnableScopesByName("+service");
  EXPECT_EQ("service+wifi", logger_->GetEnabledScopeNames());

  logger_->EnableScopesByName("+vpn+wifi");
  EXPECT_EQ("service+vpn+wifi", logger_->GetEnabledScopeNames());

  logger_->EnableScopesByName("-wifi");
  EXPECT_EQ("service+vpn", logger_->GetEnabledScopeNames());

  logger_->EnableScopesByName("-vpn-service+wifi");
  EXPECT_EQ("wifi", logger_->GetEnabledScopeNames());

  logger_->EnableScopesByName("+-wifi-");
  EXPECT_EQ("", logger_->GetEnabledScopeNames());

  logger_->EnableScopesByName("-vpn+vpn+wifi-wifi");
  EXPECT_EQ("vpn", logger_->GetEnabledScopeNames());

  logger_->EnableScopesByName("wifi");
  EXPECT_EQ("wifi", logger_->GetEnabledScopeNames());

  logger_->EnableScopesByName("");
  EXPECT_EQ("", logger_->GetEnabledScopeNames());
}

TEST_F(ScopeLoggerTest, EnableScopesByNameWithUnknownScopeName) {
  logger_->EnableScopesByName("foo");
  EXPECT_EQ("", logger_->GetEnabledScopeNames());

  logger_->EnableScopesByName("wifi+foo+vpn");
  EXPECT_EQ("vpn+wifi", logger_->GetEnabledScopeNames());
}

TEST_F(ScopeLoggerTest, SetScopeEnabled) {
  EXPECT_FALSE(ScopeLogger::IsLogEnabled(ScopeLogger::kService, 0));

  logger_->SetScopeEnabled(ScopeLogger::kService, true);
  EXPECT_TRUE(ScopeLogger::IsLogEnabled(ScopeLogger::kService, 0));

  logger_->SetScopeEnabled(ScopeLogger::kService, false);
  EXPECT_FALSE(ScopeLogger::IsLogEnabled(ScopeLogger::kService, 0));
}

TEST_F(ScopeLoggerTest, SetVerboseLevel) {
  logger_->SetScopeEnabled(ScopeLogger::kService, true);
  EXPECT_TRUE(logger_->IsLogEnabled(ScopeLogger::kService, 0));
  EXPECT_FALSE(logger_->IsLogEnabled(ScopeLogger::kService, 1));
  EXPECT_FALSE(logger_->IsLogEnabled(ScopeLogger::kService, 2));
  EXPECT_TRUE(SLOG_IS_ON(Service, 0));
  EXPECT_FALSE(SLOG_IS_ON(Service, 1));
  EXPECT_FALSE(SLOG_IS_ON(Service, 2));

  logger_->set_verbose_level(1);
  EXPECT_TRUE(logger_->IsLogEnabled(ScopeLogger::kService, 0));
  EXPECT_TRUE(logger_->IsLogEnabled(ScopeLogger::kService, 1));
  EXPECT_FALSE(logger_->IsLogEnabled(ScopeLogger::kService, 2));
  EXPECT_TRUE(SLOG_IS_ON(Service, 0));
  EXPECT_TRUE(SLOG_IS_ON(Service, 1));
  EXPECT_FALSE(SLOG_IS_ON(Service, 2));

  logger_->set_verbose_level(2);
  EXPECT_TRUE(logger_->IsLogEnabled(ScopeLogger::kService, 0));
  EXPECT_TRUE(logger_->IsLogEnabled(ScopeLogger::kService, 1));
  EXPECT_TRUE(logger_->IsLogEnabled(ScopeLogger::kService, 2));
  EXPECT_TRUE(SLOG_IS_ON(Service, 0));
  EXPECT_TRUE(SLOG_IS_ON(Service, 1));
  EXPECT_TRUE(SLOG_IS_ON(Service, 2));

  logger_->set_verbose_level(0);
  logger_->SetScopeEnabled(ScopeLogger::kService, false);
}

class ScopeChangeTarget {
 public:
  ScopeChangeTarget() : weak_ptr_factory_(this) {}
  virtual ~ScopeChangeTarget() = default;
  MOCK_METHOD(void, Callback, (bool));
  base::RepeatingCallback<void(bool)> GetCallback() {
    return base::BindRepeating(&ScopeChangeTarget::Callback,
                               weak_ptr_factory_.GetWeakPtr());
  }

 private:
  base::WeakPtrFactory<ScopeChangeTarget> weak_ptr_factory_;
};

TEST_F(ScopeLoggerTest, LogScopeCallback) {
  ScopeChangeTarget target0;
  logger_->RegisterScopeEnableChangedCallback(ScopeLogger::kWiFi,
                                              target0.GetCallback());
  EXPECT_CALL(target0, Callback(_)).Times(0);
  // Call for a scope other than registered-for.
  logger_->EnableScopesByName("+vpn");
  // Change to the same value as default.
  logger_->EnableScopesByName("-wifi");
  testing::Mock::VerifyAndClearExpectations(&target0);

  EXPECT_CALL(target0, Callback(true)).Times(1);
  logger_->EnableScopesByName("+wifi");
  testing::Mock::VerifyAndClearExpectations(&target0);

  EXPECT_CALL(target0, Callback(false)).Times(1);
  logger_->EnableScopesByName("");
  testing::Mock::VerifyAndClearExpectations(&target0);

  // Change to the same value as last set.
  EXPECT_CALL(target0, Callback(_)).Times(0);
  logger_->EnableScopesByName("-wifi");
  testing::Mock::VerifyAndClearExpectations(&target0);

  ScopeChangeTarget target1;
  logger_->RegisterScopeEnableChangedCallback(ScopeLogger::kWiFi,
                                              target1.GetCallback());
  EXPECT_CALL(target0, Callback(true)).Times(1);
  EXPECT_CALL(target1, Callback(true)).Times(1);
  logger_->EnableScopesByName("+wifi");
}

}  // namespace shill
