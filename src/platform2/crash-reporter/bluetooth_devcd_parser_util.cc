// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/bluetooth_devcd_parser_util.h"

#include <vector>

#include <base/containers/span.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

#include "crash-reporter/udev_bluetooth_util.h"
#include "crash-reporter/util.h"

namespace {

std::string CreateDumpEntry(const std::string& key, const std::string& value);
bool ReportDefaultPC(base::File& file, std::string* pc);

}  // namespace

namespace vendor {

namespace intel {

// More information about Intel telemetry spec: go/cros-bt-intel-telemetry

constexpr char kVendorName[] = "Intel";
constexpr int kAddrLen = 4;
constexpr uint8_t kDebugCode = 0xFF;

enum ParseErrorReason {
  kErrorFileIO,
  kErrorEventHeaderParsing,
  kErrorTlvParsing,
};

// Possible values for TlvHeader::type
enum TlvTypeId {
  kTlvExcType = 0x01,
  kTlvLineNum = 0x02,
  kTlvModule = 0x03,
  kTlvErrorId = 0x04,
  kTlvBacktrace = 0x05,
  kTlvAuxReg = 0x06,
  kTlvSubType = 0x07,
};

struct EventHeader {
  uint8_t code;
  uint8_t len;
  uint8_t prefix[3];
} __attribute__((packed));

// The telemetry data is written as a series of Type-Length-Value triplets.
// Each record starts with a TlvHeader giving the Type and Length, followed by
// a Value. The value maps to one of the structures below; the |type| field
// tells us which one.
struct TlvHeader {
  uint8_t type;
  uint8_t len;
} __attribute__((packed));

struct TlvExcType {
  uint8_t val;
} __attribute__((packed));

struct TlvLineNum {
  uint16_t val;
} __attribute__((packed));

struct TlvModule {
  uint8_t val;
} __attribute__((packed));

struct TlvErrorId {
  uint8_t val;
} __attribute__((packed));

struct TlvBacktrace {
  uint8_t val[5][kAddrLen];
} __attribute__((packed));

struct TlvAuxReg {
  uint8_t val[4][kAddrLen];
} __attribute__((packed));

struct TlvAuxRegExt {
  uint8_t val[7][kAddrLen];
} __attribute__((packed));

struct TlvSubType {
  uint8_t val;
} __attribute__((packed));

bool ParseEventHeader(base::File& file, int* data_len, std::string* line) {
  struct EventHeader evt_header;
  int ret;

  ret = file.ReadAtCurrentPos(reinterpret_cast<char*>(&evt_header),
                              sizeof(evt_header));
  if (ret < sizeof(evt_header)) {
    LOG(WARNING) << "Error reading Intel devcoredump Event Header";
    return false;
  }

  *line = CreateDumpEntry("Intel Event Header",
                          base::HexEncode(&evt_header, sizeof(evt_header)));

  if (evt_header.code != kDebugCode) {
    LOG(WARNING) << "Incorrect Intel devcoredump debug code";
    return false;
  }

  if (evt_header.len <= sizeof(evt_header.prefix)) {
    LOG(WARNING) << "Incorrect Intel devcoredump data length";
    return false;
  }

  *data_len = evt_header.len - sizeof(evt_header.prefix);

  return true;
}

bool VerifyTlvLength(struct TlvHeader& tlv_header) {
  switch (tlv_header.type) {
    case kTlvExcType:
      return tlv_header.len == sizeof(struct TlvExcType);
    case kTlvLineNum:
      return tlv_header.len == sizeof(struct TlvLineNum);
    case kTlvModule:
      return tlv_header.len == sizeof(struct TlvModule);
    case kTlvErrorId:
      return tlv_header.len == sizeof(struct TlvErrorId);
    case kTlvBacktrace:
      return tlv_header.len == sizeof(struct TlvBacktrace);
    case kTlvAuxReg:
      return tlv_header.len == sizeof(struct TlvAuxReg) ||
             tlv_header.len == sizeof(struct TlvAuxRegExt);
    case kTlvSubType:
      return tlv_header.len == sizeof(struct TlvSubType);
    default:
      // There may be other, unknown types in the data stream. Assume they have
      // the correct length since we don't understand them.
      return true;
  }
}

bool ParseTlvHeader(base::File& file, int* tlv_type, int* tlv_len) {
  struct TlvHeader tlv_header;
  int ret;

  ret = file.ReadAtCurrentPos(reinterpret_cast<char*>(&tlv_header),
                              sizeof(tlv_header));
  if (ret < sizeof(tlv_header)) {
    LOG(WARNING) << "Error reading Intel devcoredump TLV Header";
    return false;
  }

  *tlv_type = tlv_header.type;
  *tlv_len = tlv_header.len;

  if (!VerifyTlvLength(tlv_header)) {
    LOG(WARNING) << "Incorrect TLV length " << tlv_header.len
                 << " for TLV type " << tlv_header.type;
    return false;
  }

  return true;
}

bool ParseExceptionType(base::File& file, std::string* line) {
  struct TlvExcType exc_type;
  int ret;

  ret = file.ReadAtCurrentPos(reinterpret_cast<char*>(&exc_type),
                              sizeof(exc_type));
  if (ret < sizeof(exc_type)) {
    LOG(WARNING) << "Error reading Intel devcoredump Exception Type";
    return false;
  }

  *line = CreateDumpEntry("Exception Type",
                          base::HexEncode(&exc_type, sizeof(exc_type)));
  return true;
}

bool ParseLineNumber(base::File& file, std::string* line) {
  struct TlvLineNum line_num;
  int ret;

  ret = file.ReadAtCurrentPos(reinterpret_cast<char*>(&line_num),
                              sizeof(line_num));
  if (ret < sizeof(line_num)) {
    LOG(WARNING) << "Error reading Intel devcoredump Line Number";
    return false;
  }

  *line = CreateDumpEntry("Line Number",
                          base::HexEncode(&line_num, sizeof(line_num)));
  return true;
}

bool ParseModuleNumber(base::File& file, std::string* line) {
  struct TlvModule module_num;
  int ret;

  ret = file.ReadAtCurrentPos(reinterpret_cast<char*>(&module_num),
                              sizeof(module_num));
  if (ret < sizeof(module_num)) {
    LOG(WARNING) << "Error reading Intel devcoredump Module Number";
    return false;
  }

  *line = CreateDumpEntry("Module Number",
                          base::HexEncode(&module_num, sizeof(module_num)));
  return true;
}

bool ParseErrorId(base::File& file, std::string* line) {
  struct TlvErrorId error_id;
  int ret;

  ret = file.ReadAtCurrentPos(reinterpret_cast<char*>(&error_id),
                              sizeof(error_id));
  if (ret < sizeof(error_id)) {
    LOG(WARNING) << "Error reading Intel devcoredump Error Id";
    return false;
  }

  *line =
      CreateDumpEntry("Error Id", base::HexEncode(&error_id, sizeof(error_id)));
  return true;
}

bool ParseBacktrace(base::File& file, std::string* line) {
  struct TlvBacktrace trace;
  int ret;

  ret = file.ReadAtCurrentPos(reinterpret_cast<char*>(&trace), sizeof(trace));
  if (ret < sizeof(trace)) {
    LOG(WARNING) << "Error reading Intel devcoredump Call Backtrace";
    return false;
  }

  std::string traces;
  for (auto& val : trace.val) {
    base::StrAppend(&traces, {base::HexEncode(&val, kAddrLen), " "});
  }
  traces.pop_back();  // remove trailing whitespace.

  *line = CreateDumpEntry("Call Backtrace", traces);
  return true;
}

bool ParseAuxRegisters(base::File& file, std::string* pc, std::string* line) {
  struct TlvAuxReg reg;
  int ret;

  ret = file.ReadAtCurrentPos(reinterpret_cast<char*>(&reg), sizeof(reg));
  if (ret < sizeof(reg)) {
    LOG(WARNING) << "Error reading Intel devcoredump Aux Registers";
    return false;
  }

  *pc = base::HexEncode(&reg.val[1], kAddrLen);
  *line = base::StrCat(
      {CreateDumpEntry("CPSR", base::HexEncode(&reg.val[0], kAddrLen)),
       CreateDumpEntry("PC", base::HexEncode(&reg.val[1], kAddrLen)),
       CreateDumpEntry("SP", base::HexEncode(&reg.val[2], kAddrLen)),
       CreateDumpEntry("BLINK", base::HexEncode(&reg.val[3], kAddrLen))});
  return true;
}

bool ParseAuxRegistersExtended(base::File& file,
                               std::string* pc,
                               std::string* line) {
  struct TlvAuxRegExt reg;
  int ret;

  ret = file.ReadAtCurrentPos(reinterpret_cast<char*>(&reg), sizeof(reg));
  if (ret < sizeof(reg)) {
    LOG(WARNING) << "Error reading Intel devcoredump Aux Registers";
    return false;
  }

  *pc = base::HexEncode(&reg.val[1], kAddrLen);
  *line = base::StrCat(
      {CreateDumpEntry("BLINK", base::HexEncode(&reg.val[0], kAddrLen)),
       CreateDumpEntry("PC", base::HexEncode(&reg.val[1], kAddrLen)),
       CreateDumpEntry("ERSTATUS", base::HexEncode(&reg.val[2], kAddrLen)),
       CreateDumpEntry("ECR", base::HexEncode(&reg.val[3], kAddrLen)),
       CreateDumpEntry("EFA", base::HexEncode(&reg.val[4], kAddrLen)),
       CreateDumpEntry("IRQ", base::HexEncode(&reg.val[5], kAddrLen)),
       CreateDumpEntry("ICAUSE", base::HexEncode(&reg.val[6], kAddrLen))});
  return true;
}

bool ParseExceptionSubtype(base::File& file, std::string* line) {
  struct TlvSubType sub_type;
  int ret;

  ret = file.ReadAtCurrentPos(reinterpret_cast<char*>(&sub_type),
                              sizeof(sub_type));
  if (ret < sizeof(sub_type)) {
    LOG(WARNING) << "Error reading Intel devcoredump Exception Subtype";
    return false;
  }

  *line = CreateDumpEntry("Exception Subtype",
                          base::HexEncode(&sub_type, sizeof(sub_type)));
  return true;
}

bool ReportParseError(ParseErrorReason error_code, base::File& file) {
  std::string line = CreateDumpEntry("Parse Failure Reason",
                                     base::StringPrintf("%d", error_code));
  if (!file.WriteAtCurrentPosAndCheck(base::as_bytes(base::make_span(line)))) {
    return false;
  }
  return true;
}

bool ParseIntelDump(const base::FilePath& coredump_path,
                    const base::FilePath& target_path,
                    const int64_t dump_start,
                    std::string* pc) {
  base::File dump_file(coredump_path,
                       base::File::FLAG_OPEN | base::File::FLAG_READ);
  base::File target_file(target_path,
                         base::File::FLAG_OPEN | base::File::FLAG_APPEND);

  if (!target_file.IsValid()) {
    LOG(ERROR) << "Error opening file " << target_path << " Error: "
               << base::File::ErrorToString(target_file.error_details());
    return false;
  }

  if (!dump_file.IsValid()) {
    LOG(ERROR) << "Error opening file " << coredump_path << " Error: "
               << base::File::ErrorToString(dump_file.error_details());
    // Use the default value for PC and report an empty dump.
    if (!ReportDefaultPC(target_file, pc) ||
        !ReportParseError(kErrorFileIO, target_file)) {
      PLOG(ERROR) << "Error writing to target file " << target_path;
      return false;
    }
    return true;
  }

  if (dump_file.Seek(base::File::FROM_BEGIN, dump_start) == -1) {
    PLOG(ERROR) << "Error seeking file " << coredump_path;
    // Use the default value for PC and report an empty dump.
    if (!ReportDefaultPC(target_file, pc) ||
        !ReportParseError(kErrorFileIO, target_file)) {
      PLOG(ERROR) << "Error writing to target file " << target_path;
      return false;
    }
    return true;
  }

  std::string line;
  int data_len;
  bool ret = ParseEventHeader(dump_file, &data_len, &line);

  // Always report the event header whenever available, even if parsing fails.
  if (!line.empty() && !target_file.WriteAtCurrentPosAndCheck(
                           base::as_bytes(base::make_span(line)))) {
    PLOG(ERROR) << "Error writing to target file " << target_path;
    return false;
  }

  if (!ret) {
    // Use the default value for PC and report an empty dump.
    if (!ReportDefaultPC(target_file, pc) ||
        !ReportParseError(kErrorEventHeaderParsing, target_file)) {
      PLOG(ERROR) << "Error writing to target file " << target_path;
      return false;
    }
    return true;
  }

  while (data_len > 0) {
    int tlv_type;
    int tlv_len;

    line.clear();
    ret = ParseTlvHeader(dump_file, &tlv_type, &tlv_len);
    if (!ret || tlv_len <= 0 || tlv_len > data_len) {
      LOG(ERROR) << "Error parsing TLV header with type " << tlv_type
                 << " and length " << tlv_len;
      if (!ReportParseError(kErrorTlvParsing, target_file)) {
        PLOG(ERROR) << "Error writing to target file " << target_path;
        return false;
      }
      break;
    }

    switch (tlv_type) {
      case kTlvExcType:
        ret = ParseExceptionType(dump_file, &line);
        break;
      case kTlvLineNum:
        ret = ParseLineNumber(dump_file, &line);
        break;
      case kTlvModule:
        ret = ParseModuleNumber(dump_file, &line);
        break;
      case kTlvErrorId:
        ret = ParseErrorId(dump_file, &line);
        break;
      case kTlvBacktrace:
        ret = ParseBacktrace(dump_file, &line);
        break;
      case kTlvAuxReg:
        if (tlv_len == sizeof(struct TlvAuxReg)) {
          ret = ParseAuxRegisters(dump_file, pc, &line);
        } else {
          ret = ParseAuxRegistersExtended(dump_file, pc, &line);
        }
        break;
      case kTlvSubType:
        ret = ParseExceptionSubtype(dump_file, &line);
        break;
      default:
        if (dump_file.Seek(base::File::FROM_CURRENT, tlv_len) == -1) {
          PLOG(ERROR) << "Error seeking file " << coredump_path;
          ret = false;
        }
        break;
    }

    if (!ret) {
      // Do not continue if parsing of any of the TLV fails because once we are
      // out of sync with the dump, parsing further information is going to be
      // erroneous information.
      LOG(ERROR) << "Error parsing TLV with type " << tlv_type << " and length "
                 << tlv_len;
      if (!ReportParseError(kErrorTlvParsing, target_file)) {
        PLOG(ERROR) << "Error writing to target file " << target_path;
        return false;
      }
      break;
    }

    if (!line.empty() && !target_file.WriteAtCurrentPosAndCheck(
                             base::as_bytes(base::make_span(line)))) {
      PLOG(ERROR) << "Error writing to target file " << target_path;
      return false;
    }

    data_len -= (sizeof(struct TlvHeader) + tlv_len);
  }

  if (pc->empty()) {
    // If no PC found in the coredump blob, use the default value for PC
    if (!ReportDefaultPC(target_file, pc)) {
      PLOG(ERROR) << "Error writing to target file " << target_path;
      return false;
    }
  }

  return true;
}

}  // namespace intel

}  // namespace vendor

namespace {

constexpr char kCoredumpMetaHeader[] = "Bluetooth devcoredump";
constexpr char kCoredumpDataHeader[] = "--- Start dump ---";
constexpr char kCoredumpDefaultPC[] = "00000000";
const std::vector<std::string> kCoredumpState = {
    "Devcoredump Idle",  "Devcoredump Active",  "Devcoredump Complete",
    "Devcoredump Abort", "Devcoredump Timeout",
};

std::string CreateDumpEntry(const std::string& key, const std::string& value) {
  return base::StrCat({key, "=", value, "\n"});
}

int64_t GetDumpPos(base::File& file) {
  return file.Seek(base::File::FROM_CURRENT, 0);
}

bool ReportDefaultPC(base::File& file, std::string* pc) {
  *pc = kCoredumpDefaultPC;
  std::string line = CreateDumpEntry("PC", kCoredumpDefaultPC);
  if (!file.WriteAtCurrentPosAndCheck(base::as_bytes(base::make_span(line)))) {
    return false;
  }
  return true;
}

// Cannot use base::file_util::CopyFile() here as it copies the entire file,
// whereas SaveDumpData() needs to copy only the part of the file.
bool SaveDumpData(const base::FilePath& coredump_path,
                  const base::FilePath& target_path,
                  int64_t dump_start) {
  // Overwrite if the output file already exists. It makes more sense for the
  // parser binary as a standalone tool to overwrite than to fail when a file
  // exists.
  base::File target_file(
      target_path, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  if (!target_file.IsValid()) {
    LOG(ERROR) << "Error opening file " << target_path << " Error: "
               << base::File::ErrorToString(target_file.error_details());
    return false;
  }

  std::string coredump_content;
  if (!base::ReadFileToString(coredump_path, &coredump_content)) {
    PLOG(ERROR) << "Error reading coredump file " << coredump_path;
    return false;
  }

  if (!target_file.WriteAtCurrentPosAndCheck(base::as_bytes(base::make_span(
          coredump_content.substr(dump_start, std::string::npos))))) {
    PLOG(ERROR) << "Error writing to target file " << target_path;
    return false;
  }

  LOG(INFO) << "Binary devcoredump data: " << target_path;

  return true;
}

bool ParseDumpHeader(const base::FilePath& coredump_path,
                     const base::FilePath& target_path,
                     int64_t* data_pos,
                     std::string* driver_name,
                     std::string* vendor_name,
                     std::string* controller_name) {
  base::File dump_file(coredump_path,
                       base::File::FLAG_OPEN | base::File::FLAG_READ);
  // Overwrite if the output file already exists. It makes more sense for the
  // parser binary as a standalone tool to overwrite than to fail when a file
  // exists.
  base::File target_file(
      target_path, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  std::string line;

  if (!dump_file.IsValid()) {
    LOG(ERROR) << "Error opening file " << coredump_path << " Error: "
               << base::File::ErrorToString(dump_file.error_details());
    return false;
  }

  if (!target_file.IsValid()) {
    LOG(ERROR) << "Error opening file " << target_path << " Error: "
               << base::File::ErrorToString(target_file.error_details());
    return false;
  }

  while (util::GetNextLine(dump_file, line)) {
    if (line[0] == '\0') {
      // After updating the devcoredump state, the Bluetooth HCI Devcoredump
      // API adds a '\0' at the end. Remove it before splitting the line.
      line.erase(0, 1);
    }
    if (line == kCoredumpMetaHeader) {
      // Skip the header
      continue;
    }
    if (line == kCoredumpDataHeader) {
      // End of devcoredump header fields
      break;
    }

    std::vector<std::string> fields = SplitString(
        line, ":", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    if (fields.size() < 2) {
      LOG(ERROR) << "Invalid bluetooth devcoredump header line: " << line;
      return false;
    }

    std::string& key = fields[0];
    std::string& value = fields[1];

    if (key == "State") {
      int state;
      if (base::StringToInt(value, &state) && state >= 0 &&
          state < kCoredumpState.size()) {
        value = kCoredumpState[state];
      }
    } else if (key == "Driver") {
      *driver_name = value;
    } else if (key == "Vendor") {
      *vendor_name = value;
    } else if (key == "Controller Name") {
      *controller_name = value;
    }

    if (!target_file.WriteAtCurrentPosAndCheck(
            base::as_bytes(base::make_span(CreateDumpEntry(key, value))))) {
      PLOG(ERROR) << "Error writing to target file " << target_path;
      return false;
    }
  }

  *data_pos = GetDumpPos(dump_file);

  if (driver_name->empty() || vendor_name->empty() ||
      controller_name->empty()) {
    // If any of the required fields are missing, close the target file and
    // delete it.
    target_file.Close();
    if (!base::DeleteFile(target_path)) {
      LOG(ERROR) << "Error deleting file " << target_path;
    }
    return false;
  }

  return true;
}

bool ParseDumpData(const base::FilePath& coredump_path,
                   const base::FilePath& target_path,
                   const int64_t dump_start,
                   const std::string& vendor_name,
                   std::string* pc,
                   const bool save_dump_data) {
  if (save_dump_data) {
    // Save a copy of dump data on developer image. This is not attached with
    // the crash report, used only for development purpose.
    if (!SaveDumpData(coredump_path, target_path.ReplaceExtension("data"),
                      dump_start)) {
      LOG(ERROR) << "Error saving bluetooth devcoredump data";
    }
  }

  if (vendor_name == vendor::intel::kVendorName) {
    return vendor::intel::ParseIntelDump(coredump_path, target_path, dump_start,
                                         pc);
  }

  LOG(WARNING) << "Unsupported bluetooth devcoredump vendor - " << vendor_name;

  // Since no supported vendor found, use the default value for PC and
  // return true to report the crash event.
  base::File target_file(target_path,
                         base::File::FLAG_OPEN | base::File::FLAG_APPEND);
  if (!target_file.IsValid()) {
    LOG(ERROR) << "Error opening file " << target_path << " Error: "
               << base::File::ErrorToString(target_file.error_details());
    return false;
  }

  if (!ReportDefaultPC(target_file, pc)) {
    PLOG(ERROR) << "Error writing to target file " << target_path;
    return false;
  }

  return true;
}

}  // namespace

namespace bluetooth_util {

bool ParseBluetoothCoredump(const base::FilePath& coredump_path,
                            const base::FilePath& output_dir,
                            const bool save_dump_data,
                            std::string* crash_sig) {
  std::string driver_name;
  std::string vendor_name;
  std::string controller_name;
  int64_t data_pos;
  std::string pc;

  LOG(INFO) << "Input coredump path: " << coredump_path;

  base::FilePath target_path = coredump_path.ReplaceExtension("txt");
  if (!output_dir.empty()) {
    LOG(INFO) << "Output dir: " << output_dir;
    target_path = output_dir.Append(target_path.BaseName());
  }
  LOG(INFO) << "Parsed coredump path: " << target_path;

  if (!ParseDumpHeader(coredump_path, target_path, &data_pos, &driver_name,
                       &vendor_name, &controller_name)) {
    LOG(ERROR) << "Error parsing bluetooth devcoredump header";
    return false;
  }

  if (!ParseDumpData(coredump_path, target_path, data_pos, vendor_name, &pc,
                     save_dump_data)) {
    LOG(ERROR) << "Error parsing bluetooth devcoredump data";
    return false;
  }

  *crash_sig = bluetooth_util::CreateCrashSig(driver_name, vendor_name,
                                              controller_name, pc);

  return true;
}

}  // namespace bluetooth_util
