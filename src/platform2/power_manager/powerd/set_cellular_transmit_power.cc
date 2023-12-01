// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Helper program for setting radio transmit power of a cellular modem.

#include <stdlib.h>

#include <string>

#include <base/at_exit.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

namespace {

constexpr char kSysfsGpioRoot[] = "/sys/class/gpio";

class Gpio {
 public:
  // |gpio_number| is the GPIO number recognized by the kernel, which equals to
  // the base value of the GPIO chip plus an offset. |active_high| indicates if
  // the GPIO signal is active high or not.
  Gpio(uint32_t gpio_number, bool active_high)
      : gpio_number_(gpio_number), active_high_(active_high) {}
  Gpio(const Gpio&) = delete;
  Gpio& operator=(const Gpio&) = delete;

  ~Gpio() = default;

  // Asserts the GPIO signal. If |active_high_| is true, a value 1 is output to
  // the GPIO node. Otherwise, a value 0 is output.
  bool Assert() { return Set(active_high_ ? true : false); }

  // De-asserts the GPIO signal. If |active_high_| is true, a value 0 is output
  // to the GPIO node. Otherwise, a value 1 is output.
  bool Deassert() { return Set(active_high_ ? false : true); }

 private:
  // Exports the sysfs entry for the GPIO node so that the attributes for the
  // GPIO node can then be accessed through sysfs.  It effectively does 'echo
  // ${gpio_number} > /sys/class/gpio/export'.  Returns true if the sysfs entry
  // has been successfully exported.
  bool Export() {
    base::FilePath gpio_path = GetSysfsGpioPath();
    if (base::PathExists(gpio_path))
      return true;

    base::FilePath export_file =
        base::FilePath(kSysfsGpioRoot).Append("export");
    if (!base::PathExists(export_file)) {
      LOG(ERROR) << "File not found: " << export_file.value();
      return false;
    }

    std::string export_value = base::NumberToString(gpio_number_);
    if (!base::WriteFile(export_file, export_value.data(),
                         export_value.size())) {
      PLOG(ERROR) << "Could not write to " << export_file.value();
      return false;
    }

    if (!base::PathExists(gpio_path)) {
      LOG(ERROR) << "Could not export GPIO " << gpio_number_;
      return false;
    }

    return true;
  }

  // Sets the value of the GPIO node to 1 if |value_high| is true, or 0
  // otherwise. Returns true if the value has been successfully set.
  bool Set(bool value_high) {
    if (!Export())
      return false;

    base::FilePath direction_file = GetSysfsGpioPath().Append("direction");
    std::string direction_value = value_high ? "high" : "low";
    if (!base::WriteFile(direction_file, direction_value.data(),
                         direction_value.size())) {
      PLOG(ERROR) << "Could not write to " << direction_file.value();
      return false;
    }

    base::FilePath value_file = GetSysfsGpioPath().Append("value");
    std::string final_value;
    if (!base::ReadFileToString(value_file, &final_value)) {
      PLOG(ERROR) << "Could not read from " << value_file.value();
      return false;
    }

    base::TrimWhitespaceASCII(final_value, base::TRIM_ALL, &final_value);
    std::string expected_value = value_high ? "1" : "0";
    if (final_value != expected_value) {
      LOG(ERROR) << base::StringPrintf(
          "Could not set GPIO %u to %s (expected value %s, got %s)",
          gpio_number_, direction_value.c_str(), expected_value.c_str(),
          final_value.c_str());
      return false;
    }

    return true;
  }

  // Returns the sysfs path for the GPIO node, i.e.
  // /sys/class/gpio/gpio${gpio_number}.
  base::FilePath GetSysfsGpioPath() const {
    return base::FilePath(kSysfsGpioRoot)
        .Append(base::StringPrintf("gpio%u", gpio_number_));
  }

  const uint32_t gpio_number_;
  const bool active_high_;
};

}  // namespace

int main(int argc, char* argv[]) {
  // The dynamic power reduction (DPR) pin on a M.2 modem module is an active
  // low signal that controls the reduction of radio transmit power. It's
  // typically mapped to a GPIO on the AP, which can be controlled over sysfs.
  DEFINE_int32(gpio, -1,
               "GPIO number for the modem dynamic power reduction pin");
  DEFINE_bool(low, false, "Reduce transmit power");

  brillo::FlagHelper::Init(argc, argv, "Set cellular transmit power mode");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  if (FLAGS_gpio < 0) {
    LOG(ERROR) << "Invalid GPIO number: " << FLAGS_gpio;
    return EXIT_FAILURE;
  }

  Gpio gpio(FLAGS_gpio, false /* active_high */);
  bool ok = FLAGS_low ? gpio.Assert() : gpio.Deassert();
  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
