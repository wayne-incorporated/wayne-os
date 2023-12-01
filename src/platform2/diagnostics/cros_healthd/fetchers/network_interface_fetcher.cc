// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/network_interface_fetcher.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_tokenizer.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <re2/re2.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/cros_healthd/utils/callback_barrier.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using OptionalProbeErrorPtr = std::optional<mojom::ProbeErrorPtr>;
constexpr auto kInterfaceNameRegex = R"(\s*Interface\s+([A-Za-z0-9]+)\s*)";
constexpr auto kLinkNoConnectionRegex = R"((Not\s+connected.)\s*)";
constexpr auto kAccessPointRegex =
    R"(Connected\s+to\s+(\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}).*)";
constexpr auto kEncryptionRegex = R"(\s*(capability:\s+\w+\s+Privacy).+)";
// Parse the fifth line from BSS line to get encryption state.
constexpr uint32_t kEncryptionLineOffset = 5;

// This function will return the value with OutputType of first token if the
// second token matches with <unit_name>.
// Example with buffer "500 MBit/s", unit_name "Mbit/s", the function shall
// return 500.
template <typename OutputType>
bool GetDoubleValueWithUnit(const std::string& buffer,
                            const std::string& unit_name,
                            OutputType* out) {
  base::StringTokenizer t(buffer, " ");
  double value;
  if (t.GetNext() && base::StringToDouble(t.token(), &value) && t.GetNext() &&
      t.token() == unit_name) {
    *out = static_cast<OutputType>(value);
    return true;
  }
  return false;
}

class State {
 public:
  State();
  State(const State&) = delete;
  State& operator=(const State&) = delete;
  ~State();

  void HandleInterfaceName(Context* context,
                           base::ScopedClosureRunner on_complete,
                           mojom::ExecutedProcessResultPtr result);

  void HandleLink(Context* context,
                  base::ScopedClosureRunner on_complete,
                  mojom::ExecutedProcessResultPtr result);

  void HandleInfo(mojom::ExecutedProcessResultPtr result);

  void HandleScanDump(mojom::ExecutedProcessResultPtr result);

  void HandlePowerSchema(const std::optional<std::string>& content);

  void HandleResult(FetchNetworkInterfaceInfoCallback callback, bool success);

  bool CheckIwResult(const mojom::ExecutedProcessResultPtr& result);

 private:
  mojom::WirelessInterfaceInfoPtr wireless_info_;
  mojom::ProbeErrorPtr error_;
};

State::State() {
  wireless_info_ = mojom::WirelessInterfaceInfo::New();
}

State::~State() = default;

bool State::CheckIwResult(const mojom::ExecutedProcessResultPtr& result) {
  // TODO(chungsheng): Revisit `&& result->err.empty()`. This raise error if
  // stderr is not empty even if return code is 0. Not sure if it is necessary
  // but it was added without comment in the original CL so leave it unchanged.
  if (result->return_code == EXIT_SUCCESS && result->err.empty()) {
    return true;
  }
  error_ = CreateAndLogProbeError(
      mojom::ErrorType::kSystemUtilityError,
      "Failed to run iw command, error code: " +
          base::NumberToString(result->return_code) + ", " + result->err);
  return false;
}

// This function handles the callback from executor()->GetScanDump. It will
// extract data of tx power from "iw <interface> scan dump" command.
void State::HandleScanDump(mojom::ExecutedProcessResultPtr result) {
  DCHECK(wireless_info_);
  DCHECK(wireless_info_->wireless_link_info);
  if (!CheckIwResult(result)) {
    return;
  }
  std::string output = result->out;
  std::vector<std::string> lines = base::SplitString(
      output, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  std::string encryption;
  wireless_info_->wireless_link_info->encyption_on = false;
  // Example of bss_str line: "BSS b0:e4:d5:6f:65:1b(on wlan0) -- associated".
  std::string bss_str =
      "BSS " + wireless_info_->wireless_link_info->access_point_address_str +
      "(on " + wireless_info_->interface_name + ") -- associated";
  for (uint32_t index = 0; index < lines.size(); index++) {
    if (lines[index] == bss_str) {
      // Only look at Privacy bit of AP that the WiFi adapter connected to.
      if (((index + kEncryptionLineOffset) < lines.size()) &&
          (RE2::FullMatch(lines[index + kEncryptionLineOffset],
                          kEncryptionRegex, &encryption))) {
        wireless_info_->wireless_link_info->encyption_on = true;
      }
      break;
    }
  }
}

// This function handles the callback from executor()->GetInfo. It will
// extract data of tx power from "iw <interface> info" command.
void State::HandleInfo(mojom::ExecutedProcessResultPtr result) {
  DCHECK(wireless_info_);
  DCHECK(wireless_info_->wireless_link_info);
  if (!CheckIwResult(result)) {
    return;
  }
  std::string output = result->out;
  std::vector<std::string> lines = base::SplitString(
      output, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  bool tx_power_found = false;
  for (const auto& line : lines) {
    base::StringTokenizer t(line, " ");
    if (t.GetNext() && t.token() == "txpower") {
      double tx_power;
      if (t.GetNext() && base::StringToDouble(t.token(), &tx_power) &&
          t.GetNext() && t.token() == "dBm") {
        wireless_info_->wireless_link_info->tx_power_dBm = (int32_t)tx_power;
        tx_power_found = true;
        break;
      }
    }
  }

  if (!tx_power_found) {
    error_ =
        CreateAndLogProbeError(mojom::ErrorType::kParseError,
                               std::string(__func__) + ": txpower not found.");
    return;
  }
}

// This function handles the callback from executor()->GetLink. It will
// extract data of access point, bit rates, signal level from
// "iw <interface> link" command.
void State::HandleLink(Context* context,
                       base::ScopedClosureRunner on_complete,
                       mojom::ExecutedProcessResultPtr result) {
  DCHECK(wireless_info_);
  if (!CheckIwResult(result)) {
    return;
  }
  std::string regex_result;
  std::string output = result->out;
  // if device is not connected, return without link information.
  if (RE2::FullMatch(output, kLinkNoConnectionRegex, &regex_result)) {
    return;
  }

  wireless_info_->wireless_link_info = mojom::WirelessLinkInfo::New();
  auto& link_info = wireless_info_->wireless_link_info;
  std::vector<std::string> lines = base::SplitString(
      output, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  // Extract the first line.
  std::string first_line = lines[0];
  if (!RE2::FullMatch(first_line, kAccessPointRegex, &regex_result)) {
    error_ = CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        std::string(__func__) + ": access point not found.");
    return;
  }
  link_info->access_point_address_str = regex_result;

  // Erase the the first line of the vector so StringPairs can be used.
  lines.erase(lines.begin());

  // The buffer the original with the first time removed.
  std::string output_left = base::JoinString(lines, "\n");
  base::StringPairs keyVals;
  if (!base::SplitStringIntoKeyValuePairs(output_left, ':', '\n', &keyVals)) {
    error_ = CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        std::string(__func__) + ": cannot create key value pairs.");
    return;
  }
  bool tx_bitrate_found = false;
  bool signal_found = false;
  for (int i = 0; i < keyVals.size(); i++) {
    if (keyVals[i].first == "signal") {
      if (GetDoubleValueWithUnit(keyVals[i].second, "dBm",
                                 &link_info->signal_level_dBm)) {
        if (link_info->signal_level_dBm < -110) {
          link_info->link_quality = 0;
        } else if (link_info->signal_level_dBm > -40) {
          link_info->link_quality = 70;
        } else {
          link_info->link_quality = link_info->signal_level_dBm + 110;
        }
        signal_found = true;
      }
    } else if (keyVals[i].first == "rx bitrate") {
      GetDoubleValueWithUnit(keyVals[i].second, "MBit/s",
                             &link_info->rx_bit_rate_mbps);
    } else if (keyVals[i].first == "tx bitrate") {
      if (GetDoubleValueWithUnit(keyVals[i].second, "MBit/s",
                                 &link_info->tx_bit_rate_mbps)) {
        tx_bitrate_found = true;
      }
    }
  }

  if (!signal_found) {
    error_ =
        CreateAndLogProbeError(mojom::ErrorType::kParseError,
                               std::string(__func__) + ": signal not found.");
    return;
  }
  if (!tx_bitrate_found) {
    error_ = CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        std::string(__func__) + ": tx bitrate not found.");
    return;
  }

  CallbackBarrier barrier{/*on_success=*/on_complete.Release(),
                          /*on_error=*/base::DoNothing()};
  context->executor()->RunIw(mojom::Executor::IwCommand::kInfo,
                             wireless_info_->interface_name,
                             barrier.Depend(base::BindOnce(
                                 &State::HandleInfo, base::Unretained(this))));
  context->executor()->RunIw(
      mojom::Executor::IwCommand::kScanDump, wireless_info_->interface_name,
      barrier.Depend(
          base::BindOnce(&State::HandleScanDump, base::Unretained(this))));
}

// This function handles the callback from executor()->GetInterfaces. It will
// extract all the wireless interfacees from "iw dev" command.
void State::HandleInterfaceName(Context* context,
                                base::ScopedClosureRunner on_complete,
                                mojom::ExecutedProcessResultPtr result) {
  if (!CheckIwResult(result)) {
    return;
  }
  std::string regex_result;
  std::string output = result->out;
  std::vector<std::string> lines = base::SplitString(
      output, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  bool interface_found = false;
  std::string interface_name;
  for (auto& line : lines) {
    if (RE2::FullMatch(line, kInterfaceNameRegex, &interface_name)) {
      interface_found = true;
      break;
    }
  }

  if (!interface_found) {
    LOG(ERROR) << "Output of `iw dev`: " << output;
    error_ = CreateAndLogProbeError(mojom::ErrorType::kServiceUnavailable,
                                    "No wireless adapter found on the system.");
    return;
  }

  if (wireless_info_.is_null()) {
    wireless_info_ = mojom::WirelessInterfaceInfo::New();
  }
  wireless_info_->interface_name = interface_name;

  context->executor()->RunIw(
      mojom::Executor::IwCommand::kLink, wireless_info_->interface_name,
      base::BindOnce(&State::HandleLink, base::Unretained(this), context,
                     std::move(on_complete)));
}

void State::HandlePowerSchema(const std::optional<std::string>& content) {
  if (!content) {
    return;
  }
  std::string content_trimmed;
  base::TrimWhitespaceASCII(content.value(), base::TRIM_ALL, &content_trimmed);

  uint power_scheme;
  if (!base::StringToUint(content_trimmed, &power_scheme)) {
    error_ = CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert power scheme to integer: " + content_trimmed);
    return;
  }
  wireless_info_->power_management_on =
      (power_scheme == 2) || (power_scheme == 3);
}

void State::HandleResult(FetchNetworkInterfaceInfoCallback callback,
                         bool success) {
  if (!success) {
    error_ = CreateAndLogProbeError(mojom::ErrorType::kServiceUnavailable,
                                    "Some mojo callbacks were not called");
  }
  if (error_) {
    std::move(callback).Run(
        mojom::NetworkInterfaceResult::NewError(std::move(error_)));
    return;
  }
  std::vector<mojom::NetworkInterfaceInfoPtr> infos;
  infos.push_back(mojom::NetworkInterfaceInfo::NewWirelessInterfaceInfo(
      std::move(wireless_info_)));
  std::move(callback).Run(
      mojom::NetworkInterfaceResult::NewNetworkInterfaceInfo(std::move(infos)));
}

}  // namespace

// Fetch network interface information.
void FetchNetworkInterfaceInfo(Context* context,
                               FetchNetworkInterfaceInfoCallback callback) {
  auto state = std::make_unique<State>();
  State* state_ptr = state.get();
  CallbackBarrier barrier{base::BindOnce(&State::HandleResult, std::move(state),
                                         std::move(callback))};

  context->executor()->RunIw(
      mojom::Executor::IwCommand::kDev, "",
      base::BindOnce(
          &State::HandleInterfaceName, base::Unretained(state_ptr), context,
          base::ScopedClosureRunner(barrier.CreateDependencyClosure())));
  context->executor()->ReadFile(
      mojom::Executor::File::kWirelessPowerScheme,
      barrier.Depend(base::BindOnce(&State::HandlePowerSchema,
                                    base::Unretained(state_ptr))));
}

}  // namespace diagnostics
