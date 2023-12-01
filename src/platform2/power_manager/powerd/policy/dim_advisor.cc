// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/dim_advisor.h"

#include <string>
#include <utility>

#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>

#include "hps/proto_bindings/hps_service.pb.h"
#include "power_manager/common/tracing.h"
#include "power_manager/powerd/policy/state_controller.h"

namespace power_manager::policy {
namespace {

// Timeout for RequestSmartDimDecision.
static constexpr base::TimeDelta kSmartDimDecisionTimeout = base::Seconds(3);

// Timeout for GetResultHpsSense.
static constexpr base::TimeDelta kGetResultHpsSenseTimeout = base::Seconds(3);

// Timeout for disabling hps if screen is undim by the user.
static constexpr base::TimeDelta kDisableHpsTimeoutOnUserUndim =
    base::Minutes(30);

}  // namespace

DimAdvisor::DimAdvisor() : weak_ptr_factory_(this) {}

DimAdvisor::~DimAdvisor() {
  if (dbus_wrapper_)
    dbus_wrapper_->RemoveObserver(this);
}

void DimAdvisor::Init(system::DBusWrapperInterface* dbus_wrapper,
                      StateController* state_controller) {
  state_controller_ = state_controller;
  dbus_wrapper_ = dbus_wrapper;
  dbus_wrapper_->AddObserver(this);
  ml_decision_dbus_proxy_ = dbus_wrapper->GetObjectProxy(
      chromeos::kMlDecisionServiceName, chromeos::kMlDecisionServicePath);
  dbus_wrapper->RegisterForServiceAvailability(
      ml_decision_dbus_proxy_,
      base::BindOnce(&DimAdvisor::HandleMlDecisionServiceAvailableOrRestarted,
                     weak_ptr_factory_.GetWeakPtr()));
  hps_dbus_proxy_ =
      dbus_wrapper->GetObjectProxy(hps::kHpsServiceName, hps::kHpsServicePath);
  dbus_wrapper->RegisterForSignal(
      hps_dbus_proxy_, hps::kHpsServiceInterface, hps::kHpsSenseChanged,
      base::BindRepeating(&DimAdvisor::HandleHpsSenseSignal,
                          weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper->RegisterForServiceAvailability(
      hps_dbus_proxy_, base::BindOnce(&DimAdvisor::HandleHpsServiceAvailable,
                                      weak_ptr_factory_.GetWeakPtr()));
}

bool DimAdvisor::ReadyForSmartDimRequest(
    base::TimeTicks now, base::TimeDelta screen_dim_imminent_delay) const {
  return IsSmartDimEnabled() && !waiting_for_smart_dim_decision_ &&
         now - last_smart_dim_decision_request_time_ >=
             screen_dim_imminent_delay;
}

void DimAdvisor::RequestSmartDimDecision(base::TimeTicks now) {
  waiting_for_smart_dim_decision_ = true;
  last_smart_dim_decision_request_time_ = now;

  dbus::MethodCall method_call(
      chromeos::kMlDecisionServiceInterface,
      chromeos::kMlDecisionServiceShouldDeferScreenDimMethod);

  dbus_wrapper_->CallMethodAsync(
      ml_decision_dbus_proxy_, &method_call, kSmartDimDecisionTimeout,
      base::BindOnce(&DimAdvisor::HandleSmartDimResponse,
                     weak_ptr_factory_.GetWeakPtr()));
}

bool DimAdvisor::IsSmartDimEnabled() const {
  return ml_decision_service_available_;
}

bool DimAdvisor::IsHpsSenseEnabled() const {
  return hps_sense_connected_ && !hps_temporarily_disabled_;
}

void DimAdvisor::UnDimFeedback(bool undimmed_by_user) {
  // For now, we only disable if undimmed by the user.
  if (!undimmed_by_user)
    return;

  hps_temporarily_disabled_ = true;
  LOG(INFO) << "DimAdvisor::UnDimFeedback hps is temporarily disabled";
  hps_reenable_timer_.Start(FROM_HERE, kDisableHpsTimeoutOnUserUndim, this,
                            &DimAdvisor::ReenableHps);
}

void DimAdvisor::OnDBusNameOwnerChanged(const std::string& service_name,
                                        const std::string& old_owner,
                                        const std::string& new_owner) {
  // When MLDecisionService restarts.
  if (service_name == chromeos::kMlDecisionServiceName && !new_owner.empty()) {
    LOG(INFO) << "D-Bus " << service_name << " ownership changed to "
              << new_owner;
    HandleMlDecisionServiceAvailableOrRestarted(true);
  }
  // Notify StateController when HpsService stops.
  // No action required on restart since HpsService will restart with state
  // UNKNOWN, and as soon as that state changes to POSITIVE or NEGATIVE, a
  // new signal will be sent from Hps to powerd.
  if (service_name == hps::kHpsServiceName && new_owner.empty()) {
    LOG(INFO) << "D-Bus " << service_name << " ownership changed to empty.";
    HandleHpsServiceStopped();
  }
}

void DimAdvisor::HandleMlDecisionServiceAvailableOrRestarted(bool available) {
  ml_decision_service_available_ = available;
  if (!available) {
    LOG(ERROR) << "Failed waiting for ml decision service to become "
                  "available";
    return;
  }
}

void DimAdvisor::HandleHpsServiceAvailable(bool available) {
  if (!available) {
    LOG(ERROR) << "Failed waiting for Hps service to become "
                  "available";
    return;
  }

  // Send a dbus call to get the first possible hps_result.
  dbus::MethodCall method_call(hps::kHpsServiceInterface,
                               hps::kGetResultHpsSense);

  dbus_wrapper_->CallMethodAsync(
      hps_dbus_proxy_, &method_call, kGetResultHpsSenseTimeout,
      base::BindOnce(&DimAdvisor::HandleGetResultHpsSenseResponse,
                     weak_ptr_factory_.GetWeakPtr()));
}

void DimAdvisor::HandleHpsServiceStopped() {
  LOG(ERROR) << "HPS Service is stopped, disable DimAdvisor for HPS signal.";
  state_controller_->HandleHpsResultChange(hps::HpsResult::UNKNOWN);
  hps_sense_connected_ = false;
}

void DimAdvisor::HandleGetResultHpsSenseResponse(dbus::Response* response) {
  if (!response) {
    LOG(ERROR) << "D-Bus method call to " << hps::kHpsServiceInterface << "."
               << hps::kGetResultHpsSense << " failed";
    return;
  }

  dbus::MessageReader reader(response);
  hps::HpsResultProto result_proto;

  if (!reader.PopArrayOfBytesAsProto(&result_proto)) {
    LOG(ERROR) << "Can't read dbus response from " << hps::kHpsServiceInterface
               << "." << hps::kGetResultHpsSense;
    return;
  }

  // Here we should only set hps_sense_connected_ = true if the result from
  // HpsService is not UNKNOWN.
  hps_sense_connected_ = result_proto.value() != hps::HpsResult::UNKNOWN;
  // Calls StateController::HandleHpsResultChange to consume first hps result.
  state_controller_->HandleHpsResultChange(result_proto.value());
}

void DimAdvisor::HandleSmartDimResponse(dbus::Response* response) {
  DCHECK(waiting_for_smart_dim_decision_)
      << "Smart dim decision is not being waited for";

  waiting_for_smart_dim_decision_ = false;

  if (!response) {
    LOG(ERROR) << "D-Bus method call to "
               << chromeos::kMlDecisionServiceInterface << "."
               << chromeos::kMlDecisionServiceShouldDeferScreenDimMethod
               << " failed";
    return;
  }

  dbus::MessageReader reader(response);
  bool should_defer_screen_dim = false;
  if (!reader.PopBool(&should_defer_screen_dim)) {
    LOG(ERROR) << "Unable to read info from "
               << chromeos::kMlDecisionServiceInterface << "."
               << chromeos::kMlDecisionServiceShouldDeferScreenDimMethod
               << " response";
    return;
  }

  if (!should_defer_screen_dim) {
    VLOG(1) << "Smart dim decided not to defer screen dimming";
    return;
  }

  LOG(INFO) << "Smart dim decided to defer screen dimming";
  state_controller_->HandleDeferFromSmartDim();
}

void DimAdvisor::HandleHpsSenseSignal(dbus::Signal* signal) {
  // Hps sense is considered connected as soon as we get one signal from it.
  // Otherwise it maybe disabled inside HpsService.
  hps_sense_connected_ = true;

  dbus::MessageReader reader(signal);
  hps::HpsResultProto result_proto;

  if (!reader.PopArrayOfBytesAsProto(&result_proto)) {
    LOG(ERROR) << "Can't read dbus signal from " << hps::kHpsServiceInterface
               << "." << hps::kHpsSenseChanged;
    return;
  }

  LOG(INFO) << "DimAdvisor::HandleHpsSenseSignal is called with value "
            << hps::HpsResult_Name(result_proto.value());
  // Calls StateController::HandleHpsResultChange to consume new hps result.
  state_controller_->HandleHpsResultChange(result_proto.value());
}

void DimAdvisor::ReenableHps() {
  TRACE_EVENT("power", "DimAdvisor::ReenableHps");
  LOG(INFO) << "DimAdvisor::ReenableHps hps temporarily disabling is over";
  hps_temporarily_disabled_ = false;
}

}  // namespace power_manager::policy
