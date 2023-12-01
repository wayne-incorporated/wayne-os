// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/bluetooth_devcd_parser_util.h"

#include <vector>

#include <base/containers/span.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/strings/string_utils.h>

#include <gtest/gtest.h>

#include "crash-reporter/udev_bluetooth_util.h"
#include "crash-reporter/util.h"

namespace {

constexpr char kMetaHeader[] = "Bluetooth devcoredump";

std::vector<uint8_t> Flatten(const std::vector<std::vector<uint8_t>>& vec) {
  std::vector<uint8_t> flattened;
  for (const auto& v : vec) {
    flattened.insert(flattened.end(), v.begin(), v.end());
  }
  return flattened;
}

}  // namespace

class BluetoothDevcdParserUtilTest : public ::testing::Test {
 protected:
  void CreateDumpFile(const std::vector<std::string>& meta_data,
                      const std::vector<uint8_t>& data = {}) {
    std::string meta_data_str = brillo::string_utils::Join("\n", meta_data);
    std::string data_header = "\n--- Start dump ---\n";

    // Clear previous test files, if any
    ASSERT_TRUE(base::DeleteFile(dump_path_));
    ASSERT_TRUE(base::DeleteFile(target_path_));
    ASSERT_TRUE(base::DeleteFile(data_path_));

    base::File file(dump_path_,
                    base::File::FLAG_CREATE | base::File::FLAG_WRITE);

    ASSERT_TRUE(file.IsValid());

    ASSERT_TRUE(file.WriteAtCurrentPosAndCheck(
        base::as_bytes(base::make_span(meta_data_str))));

    if (!data.empty()) {
      ASSERT_TRUE(file.WriteAtCurrentPosAndCheck(
          base::as_bytes(base::make_span(data_header))));
      ASSERT_TRUE(file.WriteAtCurrentPosAndCheck(base::make_span(data)));
    }
  }

  void VerifyProcessedDump(const std::vector<std::string>& want_lines) {
    base::File file(target_path_,
                    base::File::FLAG_OPEN | base::File::FLAG_READ);
    std::string line;
    for (const auto& want : want_lines) {
      ASSERT_GT(util::GetNextLine(file, line), 0);
      EXPECT_EQ(line, want);
    }

    // Make sure there are no more lines
    ASSERT_EQ(util::GetNextLine(file, line), 0);
  }

  base::FilePath output_dir_;
  base::FilePath dump_path_;
  base::FilePath target_path_;
  base::FilePath data_path_;

 private:
  void SetUp() override {
    CHECK(tmp_dir_.CreateUniqueTempDir());
    output_dir_ = tmp_dir_.GetPath();
    dump_path_ = output_dir_.Append("bt_firmware.devcd");
    target_path_ = output_dir_.Append("bt_firmware.txt");
    data_path_ = output_dir_.Append("bt_firmware.data");
  }

  base::ScopedTempDir tmp_dir_;
};

// Test a failure case when reading the input coredump file fails.
TEST_F(BluetoothDevcdParserUtilTest, TestInvalidPath) {
  std::string sig;

  EXPECT_FALSE(bluetooth_util::ParseBluetoothCoredump(
      dump_path_.ReplaceExtension("invalid"), output_dir_, true, &sig));
}

// A key-value pair in header fields is of type "<key>: <value>". Verify
// that malformed key-value pairs are not parsed and an error is returned.
TEST_F(BluetoothDevcdParserUtilTest, TestInvalidHeaderField) {
  std::string sig;

  // Test missing value in key-value pair
  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State:",
  };
  CreateDumpFile(meta_data);
  EXPECT_FALSE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                      false, &sig));

  // Test malformed key-value pair
  meta_data = {
      kMetaHeader,
      "State 0",
  };
  CreateDumpFile(meta_data);
  EXPECT_FALSE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                      false, &sig));
}

// Verify that the devcodedump state with a value other than 0-4 is reported
// as is. For values between 0 through 4, it's equivalent human readable state
// string is reported.
TEST_F(BluetoothDevcdParserUtilTest, TestInvalidState) {
  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: -1",
      "Driver: TestDrv",
      "Vendor: TestVen",
      "Controller Name: TestCon",
  };
  CreateDumpFile(meta_data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_EQ(sig, "bt_firmware-TestDrv-TestVen_TestCon-00000000");

  base::File file(target_path_, base::File::FLAG_OPEN | base::File::FLAG_READ);
  std::string line;
  util::GetNextLine(file, line);
  EXPECT_EQ(line, "State=-1");
}

// The Driver Name, Vendor Name and Controller Name are required key-value
// pairs. Although we allow partial dumps, parsing should fail if any of
// these required keys are missing.
TEST_F(BluetoothDevcdParserUtilTest, TestMissingMetaKey) {
  std::string sig;

  // Test missing driver case
  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 0",
      "Vendor: TestVen",
      "Controller Name: TestCon",
  };
  CreateDumpFile(meta_data);
  EXPECT_FALSE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                      false, &sig));

  // Test missing vendor case
  meta_data = {
      kMetaHeader,
      "State: 0",
      "Driver: TestDrv",
      "Controller Name: TestCon",
  };
  CreateDumpFile(meta_data);
  EXPECT_FALSE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                      false, &sig));

  // Test missing controller name case
  meta_data = {
      kMetaHeader,
      "State: 0",
      "Driver: TestDrv",
      "Vendor: TestVen",
  };
  CreateDumpFile(meta_data);
  EXPECT_FALSE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                      false, &sig));
}

// After updating the devcoredump state, the Bluetooth HCI Devcoredump
// API adds a '\0' at the end of the "State:" key-value, i.e. before the
// "Driver:" key-value pair. Verify this case.
TEST_F(BluetoothDevcdParserUtilTest, TestHeaderWithNullChar) {
  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      std::string("\0Driver: TestDrv", 16),
      "Vendor: TestVen",
      "Controller Name: TestCon",
  };
  CreateDumpFile(meta_data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_EQ(sig, "bt_firmware-TestDrv-TestVen_TestCon-00000000");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete", "Driver=TestDrv", "Vendor=TestVen",
      "Controller Name=TestCon",    "PC=00000000",
  };
  VerifyProcessedDump(want_lines);
}

// A bluetooth devcoredump with just a header but no vendor specific binary
// data is a valid dump. Verify that the empty dump is reported properly.
TEST_F(BluetoothDevcdParserUtilTest, TestValidEmptyDump) {
  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      "Driver: TestDrv",
      "Vendor: TestVen",
      "Controller Name: TestCon",
  };
  CreateDumpFile(meta_data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_EQ(sig, "bt_firmware-TestDrv-TestVen_TestCon-00000000");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete", "Driver=TestDrv", "Vendor=TestVen",
      "Controller Name=TestCon",    "PC=00000000",
  };
  VerifyProcessedDump(want_lines);
}

// For debugging purposes, vendor specific binary data is stored on a
// developer images. Verify that the header is stripped off correctly and
// the binary data is stored.
TEST_F(BluetoothDevcdParserUtilTest, TestDumpData) {
  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      "Driver: TestDrv",
      "Vendor: TestVen",
      "Controller Name: TestCon",
  };
  std::vector<uint8_t> data = {'T', 'e', 's', 't', '\n'};
  CreateDumpFile(meta_data, data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     true, &sig));
  EXPECT_EQ(sig, "bt_firmware-TestDrv-TestVen_TestCon-00000000");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete", "Driver=TestDrv", "Vendor=TestVen",
      "Controller Name=TestCon",    "PC=00000000",
  };
  VerifyProcessedDump(want_lines);

  base::File file(data_path_, base::File::FLAG_OPEN | base::File::FLAG_READ);
  std::string line;
  util::GetNextLine(file, line);
  EXPECT_EQ(line, "Test");
}

// Verify all Intel TLVs are parsed correctly and the PC is included in the
// crash signature.
TEST_F(BluetoothDevcdParserUtilTest, TestIntelDumpWithPC) {
  // Clang format expands the following to one hex value per line.
  // Disable clang format to keep it as it is for better readability.
  // clang-format off
  std::vector<std::vector<uint8_t>> data_vec = {
      // Intel coredump header
      {
          0xFF, 0x00, 0x87, 0x80, 0x03,
      },
      // TLV - Exception Type
      {
          0x01, 0x01, 0x01,
      },
      // TLV - Line Number
      {
          0x02, 0x02, 0x12, 0x34,
      },
      // TLV - Module Number
      {
          0x03, 0x01, 0x02,
      },
      // TLV - Error ID
      {
          0x04, 0x01, 0x03,
      },
      // TLV - Call Backtrace - Func 1 Addr, Func2 Addr ... Func 5 Addr
      {
          0x05, 0x14, 0x00, 0x00, 0xFC, 0x4D, 0x00, 0x0C, 0x44, 0x8E, 0x00,
          0x06, 0x09, 0x28, 0x00, 0x00, 0xEE, 0x04, 0x00, 0x0C, 0x0C, 0x80,
      },
      // TLV - Aux Registers - CPSR, PC, SP, BLINK
      {
          0x06, 0x10, 0x00, 0x00, 0x4D, 0xFC, 0x00, 0x0C, 0x8E, 0x44, 0x00,
          0x06, 0x28, 0x09, 0x00, 0x00, 0x04, 0xEE,
      },
      // TLV - Exception Subtype
      {
          0x07, 0x01, 0x04,
      },
  };
  // clang-format on
  std::vector<uint8_t> data = Flatten(data_vec);

  // As per the Intel coredump format, 2nd byte of the data stores length of the
  // dump data excluding size of the 1st byte (code) and 2nd byte (length byte).
  data[1] = data.size() - 2;

  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      "Driver: btusb",
      "Vendor: Intel",
      "Controller Name: 0x12",
  };
  CreateDumpFile(meta_data, data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_EQ(sig, "bt_firmware-btusb-Intel_0x12-000C8E44");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete",
      "Driver=btusb",
      "Vendor=Intel",
      "Controller Name=0x12",
      "Intel Event Header=FF3B878003",
      "Exception Type=01",
      "Line Number=1234",
      "Module Number=02",
      "Error Id=03",
      "Call Backtrace=0000FC4D 000C448E 00060928 0000EE04 000C0C80",
      "CPSR=00004DFC",
      "PC=000C8E44",
      "SP=00062809",
      "BLINK=000004EE",
      "Exception Subtype=04",
  };
  VerifyProcessedDump(want_lines);
}

// Verify Aux Register Extended TLV is parsed correctly and the PC is included
// in the crash signature.
TEST_F(BluetoothDevcdParserUtilTest, TestIntelDumpWithAuxRegExt) {
  // Clang format expands the following to one hex value per line.
  // Disable clang format to keep it as it is for better readability.
  // clang-format off
  std::vector<std::vector<uint8_t>> data_vec = {
      // Intel coredump header
      {
          0xFF, 0x00, 0x87, 0x80, 0x03,
      },
      // TLV - Aux Registers Ext - BLINK, PC, ERSTATUS, ECR, EFA, IRQ, ICAUSE
      {
          0x06, 0x1C, 0x00, 0x00, 0x4D, 0xFC, 0x00, 0x0C, 0x8E, 0x44, 0x00,
          0x06, 0x28, 0x09, 0x00, 0x00, 0x04, 0xEE, 0x00, 0x0C, 0x44, 0x8E,
          0x00, 0x06, 0x09, 0x28, 0x00, 0x00, 0xEE, 0x04,
      },
  };
  // clang-format on
  std::vector<uint8_t> data = Flatten(data_vec);

  // As per the Intel coredump format, 2nd byte of the data stores length of the
  // dump data excluding size of the 1st byte (code) and 2nd byte (length byte).
  data[1] = data.size() - 2;

  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      "Driver: btusb",
      "Vendor: Intel",
      "Controller Name: 0x12",
  };
  CreateDumpFile(meta_data, data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_EQ(sig, "bt_firmware-btusb-Intel_0x12-000C8E44");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete",
      "Driver=btusb",
      "Vendor=Intel",
      "Controller Name=0x12",
      "Intel Event Header=FF21878003",
      "BLINK=00004DFC",
      "PC=000C8E44",
      "ERSTATUS=00062809",
      "ECR=000004EE",
      "EFA=000C448E",
      "IRQ=00060928",
      "ICAUSE=0000EE04",
  };
  VerifyProcessedDump(want_lines);
}

// Verify if the TLV containing PC is not present, a default PC (00000000)
// is reported.
TEST_F(BluetoothDevcdParserUtilTest, TestIntelDumpWithoutPC) {
  // Clang format expands the following to one hex value per line.
  // Disable clang format to keep it as it is for better readability.
  // clang-format off
  std::vector<std::vector<uint8_t>> data_vec = {
      // Intel coredump header
      {
          0xFF, 0x00, 0x87, 0x80, 0x03,
      },
      // TLV - Exception Type
      {
          0x01, 0x01, 0x01,
      },
      // TLV - Line Number
      {
          0x02, 0x02, 0x12, 0x34,
      },
      // TLV - Module Number
      {
          0x03, 0x01, 0x02,
      },
      // TLV - Error ID
      {
          0x04, 0x01, 0x03,
      },
      // TLV - Call Backtrace - Func 1 Addr, Func2 Addr ... Func 5 Addr
      {
          0x05, 0x14, 0x00, 0x00, 0xFC, 0x4D, 0x00, 0x0C, 0x44, 0x8E, 0x00,
          0x06, 0x09, 0x28, 0x00, 0x00, 0xEE, 0x04, 0x00, 0x0C, 0x0C, 0x80,
      },
      // TLV - Exception Subtype
      {
          0x07, 0x01, 0x04,
      },
  };
  // clang-format on
  std::vector<uint8_t> data = Flatten(data_vec);

  // As per the Intel coredump format, 2nd byte of the data stores length of the
  // dump data excluding size of the 1st byte (code) and 2nd byte (length byte).
  data[1] = data.size() - 2;

  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      "Driver: btusb",
      "Vendor: Intel",
      "Controller Name: 0x12",
  };
  CreateDumpFile(meta_data, data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_EQ(sig, "bt_firmware-btusb-Intel_0x12-00000000");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete",
      "Driver=btusb",
      "Vendor=Intel",
      "Controller Name=0x12",
      "Intel Event Header=FF29878003",
      "Exception Type=01",
      "Line Number=1234",
      "Module Number=02",
      "Error Id=03",
      "Call Backtrace=0000FC4D 000C448E 00060928 0000EE04 000C0C80",
      "Exception Subtype=04",
      "PC=00000000",
  };
  VerifyProcessedDump(want_lines);
}

// Verify that the vendor specific private TLV is not processed and not
// included in the parsed devcoredump.
TEST_F(BluetoothDevcdParserUtilTest, TestIntelDumpPrivateTLV) {
  // Clang format expands the following to one hex value per line.
  // Disable clang format to keep it as it is for better readability.
  // clang-format off
  std::vector<std::vector<uint8_t>> data_vec = {
      // Intel coredump header
      {
          0xFF, 0x00, 0x87, 0x80, 0x03,
      },
      // TLV - Exception Type
      {
          0x01, 0x01, 0x01,
      },
      // Random Private TLV
      {
          0x12, 0x01, 0x03,
      },
      // TLV - Module Number
      {
          0x03, 0x01, 0x02,
      },
  };
  // clang-format on
  std::vector<uint8_t> data = Flatten(data_vec);

  // As per the Intel coredump format, 2nd byte of the data stores length of the
  // dump data excluding size of the 1st byte (code) and 2nd byte (length byte).
  data[1] = data.size() - 2;

  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      "Driver: btusb",
      "Vendor: Intel",
      "Controller Name: 0x12",
  };
  CreateDumpFile(meta_data, data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_EQ(sig, "bt_firmware-btusb-Intel_0x12-00000000");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete",
      "Driver=btusb",
      "Vendor=Intel",
      "Controller Name=0x12",
      "Intel Event Header=FF0C878003",
      "Exception Type=01",
      "Module Number=02",
      "PC=00000000",
  };
  VerifyProcessedDump(want_lines);
}

// Verify that when a TLV with incorrect length is encountered, parsing of the
// remaining devcoredump is skipped but already parsed data is still reported.
TEST_F(BluetoothDevcdParserUtilTest, TestIntelDumpWithIncorrectTypeLen) {
  // Clang format expands the following to one hex value per line.
  // Disable clang format to keep it as it is for better readability.
  // clang-format off
  std::vector<std::vector<uint8_t>> data_vec = {
      // Intel coredump header
      {
          0xFF, 0x00, 0x87, 0x80, 0x03,
      },
      // TLV - Exception Type with incorrect Type Len D0, should skip parsing of
      // all remaining tuples
      {
          0x01, 0xD0, 0x01,
      },
      // TLV - Line Number
      {
          0x02, 0x02, 0x12, 0x34,
      },
      // TLV - Module Number
      {
          0x03, 0x01, 0x02,
      },
      // TLV - Error ID
      {
          0x04, 0x01, 0x03,
      },
      // TLV - Call Backtrace - Func 1 Addr, Func2 Addr ... Func 5 Addr
      {
          0x05, 0x14, 0x00, 0x00, 0xFC, 0x4D, 0x00, 0x0C, 0x44, 0x8E, 0x00,
          0x06, 0x09, 0x28, 0x00, 0x00, 0xEE, 0x04, 0x00, 0x0C, 0x0C, 0x80,
      },
      // TLV - Aux Registers - CPSR, PC, SP, BLINK
      {
          0x06, 0x10, 0x00, 0x00, 0x4D, 0xFC, 0x00, 0x0C, 0x8E, 0x44, 0x00,
          0x06, 0x28, 0x09, 0x00, 0x00, 0x04, 0xEE,
      },
      // TLV - Exception Subtype
      {
          0x07, 0x01, 0x04,
      },
  };
  // clang-format on
  std::vector<uint8_t> data = Flatten(data_vec);

  // As per the Intel coredump format, 2nd byte of the data stores length of the
  // dump data excluding size of the 1st byte (code) and 2nd byte (length byte).
  data[1] = data.size() - 2;

  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      "Driver: btusb",
      "Vendor: Intel",
      "Controller Name: 0x12",
  };
  CreateDumpFile(meta_data, data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_NE(sig, "bt_firmware-btusb-Intel_0x12-000C8E44");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete",
      "Driver=btusb",
      "Vendor=Intel",
      "Controller Name=0x12",
      "Intel Event Header=FF3B878003",
      "Parse Failure Reason=2",
      "PC=00000000",
  };
  VerifyProcessedDump(want_lines);
}

// Verify that the partial devcoredump is processed successfully and all the
// available data is parsed and reported.
TEST_F(BluetoothDevcdParserUtilTest, TestIntelPartialDump) {
  // Clang format expands the following to one hex value per line.
  // Disable clang format to keep it as it is for better readability.
  // clang-format off
  std::vector<std::vector<uint8_t>> data_vec = {
      // Intel coredump header
      {
          0xFF, 0x00, 0x87, 0x80, 0x03,
      },
      // TLV - Exception Type
      {
          0x01, 0x01, 0x01,
      },
      // TLV - Module Number (Incomplete)
      {
          0x03, 0x01,
      },
  };
  // clang-format on
  std::vector<uint8_t> data = Flatten(data_vec);

  // As per the Intel coredump format, 2nd byte of the data stores length of the
  // dump data excluding size of the 1st byte (code) and 2nd byte (length byte).
  data[1] = data.size() - 2;

  // Increase the data len without actually adding any data bytes to test the
  // partial dump case.
  data[1] += 10;

  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      "Driver: btusb",
      "Vendor: Intel",
      "Controller Name: 0x12",
  };
  CreateDumpFile(meta_data, data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_EQ(sig, "bt_firmware-btusb-Intel_0x12-00000000");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete",
      "Driver=btusb",
      "Vendor=Intel",
      "Controller Name=0x12",
      "Intel Event Header=FF12878003",
      "Exception Type=01",
      "Parse Failure Reason=2",
      "PC=00000000",
  };
  VerifyProcessedDump(want_lines);
}

// Verify that the devcoredump with incorrect data length (i.e. data[1] byte)
// is processed successfully and the empty dump with just a parsed header is
// reported.
TEST_F(BluetoothDevcdParserUtilTest, TestIntelIncorrectDataLen) {
  // Clang format expands the following to one hex value per line.
  // Disable clang format to keep it as it is for better readability.
  // clang-format off
  std::vector<std::vector<uint8_t>> data_vec = {
      // Intel coredump header
      {
          0xFF, 0x00, 0x87, 0x80, 0x03,
      },
      // TLV - Exception Type
      {
          0x01, 0x01, 0x01,
      },
  };
  // clang-format on
  std::vector<uint8_t> data = Flatten(data_vec);

  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      "Driver: btusb",
      "Vendor: Intel",
      "Controller Name: 0x12",
  };
  CreateDumpFile(meta_data, data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_EQ(sig, "bt_firmware-btusb-Intel_0x12-00000000");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete",
      "Driver=btusb",
      "Vendor=Intel",
      "Controller Name=0x12",
      "Intel Event Header=FF00878003",
      "PC=00000000",
      "Parse Failure Reason=1",
  };
  VerifyProcessedDump(want_lines);
}

// Verify that the devcoredump with incorrect debug code (i.e. data[0] byte)
// is processed successfully and the empty dump with just a parsed header is
// reported.
TEST_F(BluetoothDevcdParserUtilTest, TestIntelIncorrectDebugCode) {
  // Clang format expands the following to one hex value per line.
  // Disable clang format to keep it as it is for better readability.
  // clang-format off
  std::vector<std::vector<uint8_t>> data_vec = {
      // Intel coredump header (Incorrect debug code 0xFE - should skip parsing
      // of all remaining tuples)
      {
          0xFE, 0x00, 0x87, 0x80, 0x03,
      },
      // TLV - Exception Type
      {
          0x01, 0x01, 0x01,
      },
  };
  // clang-format on
  std::vector<uint8_t> data = Flatten(data_vec);

  // As per the Intel coredump format, 2nd byte of the data stores length of the
  // dump data excluding size of the 1st byte (code) and 2nd byte (length byte).
  data[1] = data.size() - 2;

  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      "Driver: btusb",
      "Vendor: Intel",
      "Controller Name: 0x12",
  };
  CreateDumpFile(meta_data, data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_EQ(sig, "bt_firmware-btusb-Intel_0x12-00000000");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete",
      "Driver=btusb",
      "Vendor=Intel",
      "Controller Name=0x12",
      "Intel Event Header=FE06878003",
      "PC=00000000",
      "Parse Failure Reason=1",
  };
  VerifyProcessedDump(want_lines);
}

// Verify that the incomplete TLVs are processed successfully and all the other
// available data is parsed and reported.
TEST_F(BluetoothDevcdParserUtilTest, TestIntelIncompleteTLVs) {
  // Clang format expands the following to one hex value per line.
  // Disable clang format to keep it as it is for better readability.
  // clang-format off
  std::vector<std::vector<uint8_t>> tlv_list = {
      // TLV - Exception Type (incomplete)
      {
          0x01, 0x01,
      },
      // TLV - Line Number (incomplete)
      {
          0x02, 0x02,
      },
      // TLV - Module Number (incomplete)
      {
          0x03, 0x01,
      },
      // TLV - Error ID (incomplete)
      {
          0x04, 0x01,
      },
      // TLV - Call Backtrace (incomplete)
      {
          0x05, 0x14,
      },
      // TLV - Aux Registers (incomplete)
      {
          0x06, 0x10,
      },
      // TLV - Exception Subtype (incomplete)
      {
          0x07, 0x01,
      },
  };
  // clang-format on

  for (auto& tlv : tlv_list) {
    // Intel coredump header
    std::vector<uint8_t> data = {0xFF, 0x00, 0x87, 0x80, 0x03};

    // Insert TLV after the header
    data.insert(data.end(), tlv.begin(), tlv.end());

    // As per the Intel coredump format, 2nd byte of the data stores len of the
    // dump data excluding size of the 1st byte (code) and 2nd byte (len byte).
    data[1] = data.size() - 2;

    std::vector<std::string> meta_data = {
        kMetaHeader,
        "State: 2",
        "Driver: btusb",
        "Vendor: Intel",
        "Controller Name: 0x12",
    };
    CreateDumpFile(meta_data, data);

    std::string sig;
    EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                       false, &sig));
    EXPECT_EQ(sig, "bt_firmware-btusb-Intel_0x12-00000000");

    std::vector<std::string> want_lines = {
        "State=Devcoredump Complete",
        "Driver=btusb",
        "Vendor=Intel",
        "Controller Name=0x12",
        "Intel Event Header=FF05878003",
        "Parse Failure Reason=2",
        "PC=00000000",
    };
    VerifyProcessedDump(want_lines);
  }
}

// A bluetooth devcoredump with just a header but no vendor specific binary
// data is a valid dump. Verify that the empty dump is reported properly.
TEST_F(BluetoothDevcdParserUtilTest, TestIntelEmptyDump) {
  std::vector<std::string> meta_data = {
      kMetaHeader,
      "State: 2",
      "Driver: btusb",
      "Vendor: Intel",
      "Controller Name: 0x12",
  };
  CreateDumpFile(meta_data);

  std::string sig;
  EXPECT_TRUE(bluetooth_util::ParseBluetoothCoredump(dump_path_, output_dir_,
                                                     false, &sig));
  EXPECT_EQ(sig, "bt_firmware-btusb-Intel_0x12-00000000");

  std::vector<std::string> want_lines = {
      "State=Devcoredump Complete", "Driver=btusb", "Vendor=Intel",
      "Controller Name=0x12",       "PC=00000000",  "Parse Failure Reason=1",
  };
  VerifyProcessedDump(want_lines);
}
