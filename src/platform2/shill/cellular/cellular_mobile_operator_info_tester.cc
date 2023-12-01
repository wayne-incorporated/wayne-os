// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <iostream>

#include <base/logging.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <brillo/flag_helper.h>

#include "shill/cellular/apn_list.h"
#include "shill/cellular/cellular_helpers.h"
#include "shill/cellular/mobile_operator_info.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/test_event_dispatcher.h"

namespace shill {
class MyEventDispatcher : public shill::EventDispatcher {
 public:
  MyEventDispatcher() {}
  ~MyEventDispatcher() {}

  void DispatchForever() {}
  void DispatchPendingEvents() {}
  void PostDelayedTask(const base::Location& location,
                       base::OnceClosure task,
                       base::TimeDelta delay) {}
  void QuitDispatchForever() {}
};
}  // namespace shill

int main(int argc, char* argv[]) {
  DEFINE_string(mccmnc, "", "Home MCCMNC.");
  DEFINE_string(imsi, "", "Home IMSI.");
  DEFINE_string(iccid, "", "Home ICCID.");
  DEFINE_string(name, "", "Home Operator Name.");
  DEFINE_string(gid1, "", "Home GID1");
  DEFINE_string(serving_mccmnc, "", "Serving MCCMNC.");
  DEFINE_string(serving_name, "", "Serving Operator Name.");

  brillo::FlagHelper::Init(argc, argv, "cellular_mobile_operator_info_tester");

  shill::MyEventDispatcher dispatcher;
  std::unique_ptr<shill::MobileOperatorInfo> mobile_operator_info =
      std::make_unique<shill::MobileOperatorInfo>(&dispatcher, "tester");
  mobile_operator_info->ClearDatabasePaths();
  base::FilePath executable_path = base::FilePath(argv[0]).DirName();
  base::FilePath database_path =
      base::FilePath(executable_path).Append("serviceproviders.pbf");

  logging::SetMinLogLevel(logging::LOGGING_INFO);
  shill::ScopeLogger::GetInstance()->set_verbose_level(5);
  shill::ScopeLogger::GetInstance()->EnableScopesByName("cellular");

  mobile_operator_info->AddDatabasePath(database_path);
  mobile_operator_info->Init();

  if (!FLAGS_mccmnc.empty())
    mobile_operator_info->UpdateMCCMNC(FLAGS_mccmnc);

  mobile_operator_info->IsMobileNetworkOperatorKnown();

  if (!FLAGS_name.empty())
    mobile_operator_info->UpdateOperatorName(FLAGS_name);

  mobile_operator_info->IsMobileNetworkOperatorKnown();

  if (!FLAGS_iccid.empty())
    mobile_operator_info->UpdateICCID(FLAGS_iccid);

  mobile_operator_info->IsMobileNetworkOperatorKnown();

  if (!FLAGS_imsi.empty())
    mobile_operator_info->UpdateIMSI(FLAGS_imsi);

  mobile_operator_info->IsMobileNetworkOperatorKnown();

  if (!FLAGS_gid1.empty())
    mobile_operator_info->UpdateGID1(FLAGS_gid1);

  mobile_operator_info->IsMobileNetworkOperatorKnown();

  if (!FLAGS_serving_mccmnc.empty())
    mobile_operator_info->UpdateServingMCCMNC(FLAGS_serving_mccmnc);

  if (!FLAGS_serving_name.empty())
    mobile_operator_info->UpdateServingOperatorName(FLAGS_serving_name);

  mobile_operator_info->IsServingMobileNetworkOperatorKnown();

  mobile_operator_info->friendly_operator_name(/* is_roaming */ true);
  mobile_operator_info->friendly_operator_name(/* is_roaming */ false);

  // Print a small summary that can be copy pasted into a CL message
  std::stringstream report;
  report << "\ncellular_mobile_operator_info_tester report:\n";
  report << "uuid: " << mobile_operator_info->uuid() << "\n";
  report << "operator_name: " << mobile_operator_info->operator_name() << "\n";
  report << "country: " << mobile_operator_info->country() << "\n";
  report << "mccmnc: " << mobile_operator_info->mccmnc() << "\n";
  report << "serving_mccmnc: " << mobile_operator_info->serving_mccmnc()
         << "\n";
  report << "serving_uuid: " << mobile_operator_info->serving_uuid() << "\n";
  report << "serving_operator_name: "
         << mobile_operator_info->serving_operator_name() << "\n";
  report << "requires_roaming: " << std::boolalpha
         << mobile_operator_info->requires_roaming() << "\n";
  report << "IsMobileNetworkOperatorKnown: " << std::boolalpha
         << mobile_operator_info->IsMobileNetworkOperatorKnown() << "\n";
  report << "IsServingMobileNetworkOperatorKnown: " << std::boolalpha
         << mobile_operator_info->IsServingMobileNetworkOperatorKnown() << "\n";
  report << "friendly_operator_name when roaming: "
         << mobile_operator_info->friendly_operator_name(true) << "\n";
  report << "friendly_operator_name when not roaming: "
         << mobile_operator_info->friendly_operator_name(false) << "\n";

  shill::ApnList apn_list(/* merge_similar_apns */ false);
  apn_list.AddApns(mobile_operator_info->apn_list(),
                   shill::ApnList::ApnSource::kModb);
  for (const auto& it : apn_list.GetList()) {
    report << "APN: " << shill::GetPrintableApnStringmap(it) << "\n";
  }

  std::cout << report.str();
  return 0;
}
