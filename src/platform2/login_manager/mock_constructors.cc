// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/time/time.h>

#include "login_manager/fake_generator_job.h"
#include "login_manager/mock_device_policy_service.h"
#include "login_manager/mock_file_checker.h"
#include "login_manager/mock_init_daemon_controller.h"
#include "login_manager/mock_key_generator.h"
#include "login_manager/mock_liveness_checker.h"
#include "login_manager/mock_metrics.h"
#include "login_manager/mock_mitigator.h"
#include "login_manager/mock_policy_key.h"
#include "login_manager/mock_policy_service.h"
#include "login_manager/mock_policy_store.h"
#include "login_manager/mock_process_manager_service.h"
#include "login_manager/mock_session_manager.h"
#include "login_manager/mock_subprocess.h"
#include "login_manager/mock_system_utils.h"
#include "login_manager/mock_user_policy_service_factory.h"

// Per the gmock documentation, the vast majority of the time spent on
// compiling a mock class is in generating its constructor and
// destructor, as they perform non-trivial tasks.  To combat this, the
// docs recommend moving the definition of your mock class'
// constructor and destructor out of the class body and into a .cc
// file. This way, even if you #include your mock class in N files,
// the compiler only needs to generate its constructor and destructor
// once, resulting in a much faster compilation.
//
// To avoid having to add a bunch of boilerplate and a .cc file for every
// mock I define, I will simply collect the constructors all here.

namespace login_manager {

MockDevicePolicyService::MockDevicePolicyService()
    : MockDevicePolicyService(nullptr) {}
MockDevicePolicyService::MockDevicePolicyService(PolicyKey* policy_key)
    : DevicePolicyService(base::FilePath(),
                          policy_key,
                          nullptr,
                          nullptr,
                          nullptr,
                          nullptr,
                          nullptr,
                          nullptr) {}
MockDevicePolicyService::~MockDevicePolicyService() = default;

MockFileChecker::MockFileChecker() : FileChecker(base::FilePath()) {}
MockFileChecker::~MockFileChecker() = default;

MockInitDaemonController::MockInitDaemonController() = default;
MockInitDaemonController::~MockInitDaemonController() = default;

MockKeyGenerator::MockKeyGenerator() : KeyGenerator(-1, nullptr) {}
MockKeyGenerator::~MockKeyGenerator() = default;

MockLivenessChecker::MockLivenessChecker() = default;
MockLivenessChecker::~MockLivenessChecker() = default;

MockMetrics::MockMetrics() : LoginMetrics(base::FilePath()) {}
MockMetrics::~MockMetrics() = default;

MockMitigator::MockMitigator() = default;
MockMitigator::~MockMitigator() = default;

MockPolicyKey::MockPolicyKey() : PolicyKey(base::FilePath(), nullptr) {}
MockPolicyKey::~MockPolicyKey() = default;

MockPolicyService::MockPolicyService()
    : PolicyService(base::FilePath(), nullptr, nullptr, false) {}
MockPolicyService::~MockPolicyService() = default;

MockPolicyServiceDelegate::MockPolicyServiceDelegate() = default;
MockPolicyServiceDelegate::~MockPolicyServiceDelegate() = default;

MockPolicyStore::MockPolicyStore() : PolicyStore(base::FilePath()) {}
MockPolicyStore::~MockPolicyStore() = default;

MockProcessManagerService::MockProcessManagerService() = default;
MockProcessManagerService::~MockProcessManagerService() = default;

MockSessionManager::MockSessionManager() = default;
MockSessionManager::~MockSessionManager() = default;

MockSubprocess::MockSubprocess() = default;
MockSubprocess::~MockSubprocess() = default;

MockSystemUtils::MockSystemUtils() = default;
MockSystemUtils::~MockSystemUtils() = default;

MockUserPolicyServiceFactory::MockUserPolicyServiceFactory()
    : UserPolicyServiceFactory(nullptr, nullptr) {}
MockUserPolicyServiceFactory::~MockUserPolicyServiceFactory() = default;

}  // namespace login_manager
