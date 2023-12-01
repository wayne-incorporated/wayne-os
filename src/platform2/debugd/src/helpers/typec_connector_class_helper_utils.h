// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_HELPERS_TYPEC_CONNECTOR_CLASS_HELPER_UTILS_H_
#define DEBUGD_SRC_HELPERS_TYPEC_CONNECTOR_CLASS_HELPER_UTILS_H_

#include <iostream>
#include <string>
#include <vector>

#include <base/files/file_util.h>

namespace debugd {
namespace typec_connector_class_helper {

struct VdoField {
  int index;
  uint32_t mask;
  std::string description;
};

enum ProductType {
  kOther = 0,
  kPD20PassiveCable = 1,
  kPD20ActiveCable = 2,
  kPD20AMA = 3,
  kPD30PassiveCable = 4,
  kPD30ActiveCable = 5,
  kPD30AMA = 6,
  kPD30VPD = 7,
  kPD30UFP = 8,
  kPD30DFP = 9,
  kPD30DRD = 10,
  kPD31PassiveCable = 11,
  kPD31ActiveCable = 12,
  kPD31VPD = 13,
  kPD31UFP = 14,
  kPD31DFP = 15,
  kPD31DRD = 16,
};

enum PDRev {
  kNone = 0,
  kPD20 = 1,
  kPD30 = 2,
  kPD31 = 3,
};

constexpr char kTypecSysfs[] = "/sys/class/typec";
constexpr char kPortRegex[] = "port[0-9]+$";
constexpr char kPartnerAltModeRegex[] = "port[0-9]+-partner\\.[0-9]+$";
constexpr char kModeRegex[] = "mode[0-9]+$";
constexpr char kPlugRegex[] = "port[0-9]+\\-plug[0-9]+$";
constexpr char kPlugAltModeRegex[] = "port[0-9]+\\-plug[0-9]+\\.[0-9]+$";
constexpr char kPartnerPdoRegex[] = "pd[0-9]+$";
constexpr char kPdoCapabilitiesRegex[] = "(sink|source)-capabilities$";
constexpr char kPdoTypeRegex[] =
    "[0-9]+:(battery|fixed_supply|programmable_supply|variable_supply)$";

// Masks for id_header fields.
constexpr uint32_t kPDUFPProductTypeMask = 0x38000000;
constexpr uint32_t kPDDFPProductTypeMask = 0x03800000;

// Expected id_header field results.
constexpr uint32_t kPD20PassiveCableComp = 0x20000000;
constexpr uint32_t kPD20ActiveCableComp = 0x18000000;
constexpr uint32_t kPD20AMAComp = 0x28000000;
constexpr uint32_t kPD30PassiveCableComp = 0x18000000;
constexpr uint32_t kPD30ActiveCableComp = 0x20000000;
constexpr uint32_t kPD30AMAComp = 0x28000000;
constexpr uint32_t kPD30VPDComp = 0x30000000;
constexpr uint32_t kPD30HubComp = 0x08000000;
constexpr uint32_t kPD30PeripheralComp = 0x10000000;
constexpr uint32_t kPD30DFPHubComp = 0x00800000;
constexpr uint32_t kPD30DFPHostComp = 0x01000000;
constexpr uint32_t kPD30PowerBrickComp = 0x01800000;
constexpr uint32_t kPD31PassiveCableComp = 0x18000000;
constexpr uint32_t kPD31ActiveCableComp = 0x20000000;
constexpr uint32_t kPD31VPDComp = 0x30000000;
constexpr uint32_t kPD31HubComp = 0x08000000;
constexpr uint32_t kPD31PeripheralComp = 0x10000000;
constexpr uint32_t kPD31DFPHubComp = 0x00800000;
constexpr uint32_t kPD31DFPHostComp = 0x01000000;
constexpr uint32_t kPD31PowerBrickComp = 0x01800000;

// VDO descriptions to obfuscate PID/VID with unknown PD revision.
const std::vector<VdoField> kOtherIDHeaderVDO = {{16, 0xffff0000, "Undefined"}};
const std::vector<VdoField> kOtherProductVDO = {{0, 0xffff, "Undefined"}};

// VDO descriptions from the USB PD Revision 2.0 and 3.1 specifications.
const std::vector<VdoField> kPD20CertStatVDO = {{0, 0xffffffff, "XID"}};

const std::vector<VdoField> kPD20ProductVDO = {{0, 0xffff, "bcdDevice"}};

const std::vector<VdoField> kPD20IDHeaderVDO = {
    {16, 0x03ff0000, "Reserved"},
    {26, 0x04000000, "Modal Operation Supported"},
    {27, 0x38000000, "Product Type"},
    {30, 0x40000000, "USB Capable as a USB Device"},
    {31, 0x80000000, "USB Capable as a USB Host"},
};

const std::vector<VdoField> kPD20PassiveVDO = {
    {0, 0x00000007, "USB Speed"},
    {3, 0x00000008, "Reserved"},
    {4, 0x00000010, "Vbus Through Cable"},
    {5, 0x00000060, "Vbus Current Handling"},
    {7, 0x00000080, "SSRX2 Directionality Support"},
    {8, 0x00000100, "SSRX1 Directionality Support"},
    {9, 0x00000200, "SSTX2 Directionality Support"},
    {10, 0x00000400, "SSTX1 Directionality Support"},
    {11, 0x00001800, "Cable Termination Type"},
    {13, 0x0001e000, "Cable Latency"},
    {17, 0x00020000, "Reserved"},
    {18, 0x000c0000, "USB Type-C Plug to USB Type"},
    {20, 0x00f00000, "Reserved"},
    {24, 0x0f000000, "Firmware Version"},
    {28, 0xf0000000, "HW Version"},
};

const std::vector<VdoField> kPD20ActiveVDO = {
    {0, 0x00000007, "USB Speed"},
    {3, 0x00000008, "SOP'' Controller Present"},
    {4, 0x00000010, "Vbus Through Cable"},
    {5, 0x00000060, "Vbus Current Handling"},
    {7, 0x00000080, "SSRX2 Directionality Support"},
    {8, 0x00000100, "SSRX1 Directionality Support"},
    {9, 0x00000200, "SSTX2 Directionality Support"},
    {10, 0x00000400, "SSTX1 Directionality Support"},
    {11, 0x00001800, "Cable Termination Type"},
    {13, 0x0001e000, "Cable Latency"},
    {17, 0x00020000, "Reserved"},
    {18, 0x000c0000, "USB Type-C Plug to USB Type"},
    {20, 0x00f00000, "Reserved"},
    {24, 0x0f000000, "Firmware Version"},
    {28, 0xf0000000, "HW Version"},
};

const std::vector<VdoField> kPD20AMAVDO = {
    {0, 0x00000007, "USB SS Signaling Support"},
    {3, 0x00000008, "Vbus Required"},
    {4, 0x00000010, "Vconn Required"},
    {5, 0x000000e0, "Vconn Power"},
    {8, 0x00000100, "SSRX2 Directionality Support"},
    {9, 0x00000200, "SSRX1 Directionality Support"},
    {10, 0x00000400, "SSTX2 Directionality Support"},
    {11, 0x00000800, "SSTX1 Directionality Support"},
    {12, 0x00fff000, "Reserved"},
    {24, 0x0f000000, "Firmware Version"},
    {28, 0xf0000000, "Hardware Version"},
};

const std::vector<VdoField> kPD30CertStatVDO = {{0, 0xffffffff, "XID"}};

const std::vector<VdoField> kPD30ProductVDO = {{0, 0xffff, "bcdDevice"}};

const std::vector<VdoField> kPD30IDHeaderVDO = {
    {16, 0x007f0000, "Reserved"},
    {23, 0x03800000, "Product Type (DFP)"},
    {26, 0x04000000, "Modal Operation Supported"},
    {27, 0x38000000, "Product Type (UFP/Cable Plug)"},
    {30, 0x40000000, "USB Capable as a USB Device"},
    {31, 0x80000000, "USB Capable as a USB Host"},
};

const std::vector<VdoField> kPD30PassiveVDO = {
    {0, 0x00000007, "USB Speed"},
    {3, 0x00000018, "Reserved"},
    {5, 0x00000060, "Vbus Current Handling"},
    {7, 0x00000180, "Reserved"},
    {9, 0x00000600, "Maximum Vbus Voltage"},
    {11, 0x00001800, "Cable Termination Type"},
    {13, 0x0001e000, "Cable Latency"},
    {17, 0x00020000, "Reserved"},
    {18, 0x000c0000, "USB Type-C Plug to USB Type"},
    {20, 0x00100000, "Reserved"},
    {21, 0x00e00000, "VDO Version"},
    {24, 0x0f000000, "Firmware Version"},
    {28, 0xf0000000, "HW Version"},
};

const std::vector<VdoField> kPD30ActiveVDO1 = {
    {0, 0x00000007, "USB Speed"},
    {3, 0x00000008, "SOP'' Controller Present"},
    {4, 0x00000010, "Vbus Through Cable"},
    {5, 0x00000060, "Vbus Current Handling"},
    {7, 0x00000080, "SBU Type"},
    {8, 0x00000100, "SBU Supported"},
    {9, 0x00000600, "Maximum Vbus Voltage"},
    {11, 0x00001800, "Cable Termination Type"},
    {13, 0x0001e000, "Cable Latency"},
    {17, 0x00020000, "Reserved"},
    {18, 0x000c0000, "Connector Type"},
    {20, 0x00100000, "Reserved"},
    {21, 0x00e00000, "VDO Version"},
    {24, 0x0f000000, "Firmware Version"},
    {28, 0xf0000000, "HW Version"},
};

const std::vector<VdoField> kPD30ActiveVDO2 = {
    {0, 0x00000001, "USB Gen"},
    {1, 0x00000002, "Reserved"},
    {2, 0x00000004, "Optically Insulated Active Cable"},
    {3, 0x00000008, "USB Lanes Supported"},
    {4, 0x00000010, "USB 3.2 Supported"},
    {5, 0x00000020, "USB 2.0 Supported"},
    {6, 0x000000c00, "USB 2.0 Hub Hops Command"},
    {8, 0x00000100, "USB4 Supported"},
    {9, 0x00000200, "Active Element"},
    {10, 0x00000400, "Physical Connection"},
    {11, 0x00000800, "U3 to U0 Transition Mode"},
    {12, 0x00007000, "U3/CLd Power"},
    {15, 0x00008000, "Reserved"},
    {16, 0x00ff0000, "Shutdown Tempurature"},
    {24, 0xff000000, "Max Operating Tempurature"},
};

const std::vector<VdoField> kPD30AMAVDO = {
    {0, 0x00000007, "USB Highest Speed"}, {3, 0x00000008, "Vbus Required"},
    {4, 0x00000010, "Vconn Required"},    {5, 0x000000e0, "Vconn Power"},
    {8, 0x001fff00, "Reserved"},          {21, 0x00e00000, "VDO Version"},
    {24, 0x0f000000, "Firmware Version"}, {28, 0xf0000000, "Hardware Version"},
};

const std::vector<VdoField> kPD30VPDVDO = {
    {0, 0x00000001, "Charge Through Support"},
    {1, 0x0000007e, "Ground Impedance"},
    {7, 0x00001f80, "Vbus Impedance"},
    {13, 0x00002000, "Reserved"},
    {14, 0x00004000, "Charge Through Current Support"},
    {15, 0x00018000, "Maximum Vbus Voltage"},
    {17, 0x001e0000, "Reserved"},
    {21, 0x00e00000, "VDO Version"},
    {24, 0x0f000000, "Firmware Version"},
    {28, 0xf0000000, "HW Version"},
};

const std::vector<VdoField> kPD30UFPVDO1 = {
    {0, 0x00000007, "USB Highest Speed"}, {3, 0x00000038, "Alternate Modes"},
    {6, 0x00ffffc0, "Reserved"},          {24, 0x0f000000, "Device Capability"},
    {28, 0x10000000, "Reserved"},         {29, 0xe0000000, "UFP VDO Version"},
};

const std::vector<VdoField> kPD30UFPVDO2 = {
    {0, 0x0000007f, "USB3 Max Power"},  {7, 0x00003f80, "USB3 Min Power"},
    {14, 0x0000c000, "Reserved"},       {16, 0x007f0000, "USB4 Max Power"},
    {23, 0x3f800000, "USB4 Min Power"}, {30, 0xc0000000, "Reserved"},
};

const std::vector<VdoField> kPD30DFPVDO = {
    {0, 0x0000001f, "Port Number"},      {5, 0x00ffffe0, "Reserved"},
    {24, 0x07000000, "Host Capability"}, {27, 0x18000000, "Reserved"},
    {29, 0xe0000000, "DFP VDO Version"},
};

const std::vector<VdoField> kPD31CertStatVDO = {{0, 0xffffffff, "XID"}};

const std::vector<VdoField> kPD31ProductVDO = {{0, 0xffff, "bcdDevice"}};

const std::vector<VdoField> kPD31IDHeaderVDO = {
    {16, 0x001f0000, "Reserved"},
    {21, 0x00600000, "Connector Type"},
    {23, 0x03800000, "Product Type (DFP)"},
    {26, 0x04000000, "Modal Operation Supported"},
    {27, 0x38000000, "Product Type (UFP/Cable Plug)"},
    {30, 0x40000000, "USB Capable as a USB Device"},
    {31, 0x80000000, "USB Capable as a USB Host"},
};

const std::vector<VdoField> kPD31PassiveVDO = {
    {0, 0x00000007, "USB Speed"},
    {3, 0x00000018, "Reserved"},
    {5, 0x00000060, "Vbus Current Handling"},
    {7, 0x00000180, "Reserved"},
    {9, 0x00000600, "Maximum Vbus Voltage"},
    {11, 0x00001800, "Cable Termination Type"},
    {13, 0x0001e000, "Cable Latency"},
    {17, 0x00020000, "EPR Mode Cable"},
    {18, 0x000c0000, "USB Type-C Plug to USB Type"},
    {20, 0x00100000, "Reserved"},
    {21, 0x00e00000, "VDO Version"},
    {24, 0x0f000000, "Firmware Version"},
    {28, 0xf0000000, "HW Version"},
};

const std::vector<VdoField> kPD31ActiveVDO1 = {
    {0, 0x00000007, "USB Speed"},
    {3, 0x00000008, "SOP'' Controller Present"},
    {4, 0x00000010, "Vbus Through Cable"},
    {5, 0x00000060, "Vbus Current Handling"},
    {7, 0x00000080, "SBU Type"},
    {8, 0x00000100, "SBU Supported"},
    {9, 0x00000600, "Maximum Vbus Voltage"},
    {11, 0x00001800, "Cable Termination Type"},
    {13, 0x0001e000, "Cable Latency"},
    {17, 0x00020000, "EPR Mode Cable"},
    {18, 0x000c0000, "USB Type-C Plug to USB Type"},
    {20, 0x00100000, "Reserved"},
    {21, 0x00e00000, "VDO Version"},
    {24, 0x0f000000, "Firmware Version"},
    {28, 0xf0000000, "HW Version"},
};

const std::vector<VdoField> kPD31ActiveVDO2 = {
    {0, 0x00000001, "USB Gen"},
    {1, 0x00000002, "Reserved"},
    {2, 0x00000004, "Optically Insulated Active Cable"},
    {3, 0x00000008, "USB Lanes Supported"},
    {4, 0x00000010, "USB 3.2 Supported"},
    {5, 0x00000020, "USB 2.0 Supported"},
    {6, 0x000000c00, "USB 2.0 Hub Hops Command"},
    {8, 0x00000100, "USB4 Supported"},
    {9, 0x00000200, "Active Element"},
    {10, 0x00000400, "Physical Connection"},
    {11, 0x00000800, "U3 to U0 Transition Mode"},
    {12, 0x00007000, "U3/CLd Power"},
    {15, 0x00008000, "Reserved"},
    {16, 0x00ff0000, "Shutdown Tempurature"},
    {24, 0xff000000, "Max Operating Tempurature"},
};

const std::vector<VdoField> kPD31VPDVDO = {
    {0, 0x00000001, "Charge Through Support"},
    {1, 0x0000007e, "Ground Impedance"},
    {7, 0x00001f80, "Vbus Impedance"},
    {13, 0x00002000, "Reserved"},
    {14, 0x00004000, "Charge Through Current Support"},
    {15, 0x00018000, "Maximum Vbus Voltage"},
    {17, 0x001e0000, "Reserved"},
    {21, 0x00e00000, "VDO Version"},
    {24, 0x0f000000, "Firmware Version"},
    {28, 0xf0000000, "HW Version"},
};

const std::vector<VdoField> kPD31UFPVDO = {
    {0, 0x00000007, "USB Highest Speed"},
    {3, 0x00000038, "Alternate Modes"},
    {6, 0x00000040, "Vbus Required"},
    {7, 0x00000080, "Vconn Required"},
    {8, 0x00000700, "Vconn Power"},
    {11, 0x003ff800, "Reserved"},
    {22, 0x00c00000, "Connector Type (Legacy)"},
    {24, 0x0f000000, "Device Capability"},
    {28, 0x10000000, "Reserved"},
    {29, 0xe0000000, "UFP VDO Version"},
};

const std::vector<VdoField> kPD31DFPVDO = {
    {0, 0x0000001f, "Port Number"},
    {5, 0x003fffe0, "Reserved"},
    {22, 0x00c00000, "Connector Type (Legacy)"},
    {24, 0x07000000, "Host Capability"},
    {27, 0x18000000, "Reserved"},
    {29, 0xe0000000, "DFP VDO Version"},
};

// GetIndentStr returns a string to be used as an indent based on the
// provided "indent" input.
std::string GetIndentStr(int indent);

// FormatString will remove trailing whitespace and add an indent to any new
// lines.
std::string FormatString(std::string file_str, int indent);

// ParseDirsAndExecute will look at subdirectories of a given directory and
// execute a passed function on directories matching a given regular expression.
void ParseDirsAndExecute(const base::FilePath& dir,
                         int indent,
                         char const* regex,
                         void (*func)(const base::FilePath&, int));

// PrintFile will print a file's contents in a "name: content" format and also
// add indentations to multiline strings.
void PrintFile(const base::FilePath& path, int indent);

// PrintDirFiles will print all files in a directory in a "name: content"
// format.
void PrintDirFiles(const base::FilePath& dir, int indent);

// GetPDRev will read the usb_power_delivery_revision file in a given directory
// and return a PDRev enum noting the supported PD Revision.
PDRev GetPDRev(const base::FilePath& dir);

// ReadVdo reads a file containing a 32 bit VDO value and loads it into a
// uint32_t pointer. It will return true if the file read is successful and
// false otherwise.
bool ReadVdo(const base::FilePath& path, uint32_t* vdo);

// PrintVdo reads a vdo value from a text file and converts it to a uint32_t
// variable then prints out the values of each field according to the
// vdo_description. If hide_data is set, the full vdo will not be printed to
// obfuscate user information.
void PrintVdo(const base::FilePath& vdo_file,
              const std::vector<VdoField> vdo_description,
              bool hide_data,
              int indent);

// PrintAltMode will print the immediate files in an alternate mode directory,
// then print the files in a mode subdirectory.
void PrintAltMode(const base::FilePath& alt_mode, int indent);

// PrintPdos will print the immediate files in a PDO data directory, then call
// PrintPdoCapabilities to print more detailed PDO information.
void PrintPdos(const base::FilePath& pdo_path, int indent);

// PrintPdoCapabilities will print detailed information about the PDOs given
// at a device's sysfs path, including available voltages and currents.
void PrintPdoCapabilities(const base::FilePath& capabilities, int indent);

// PrintPlugInfo will print the immediate files in an plug directory, then print
// the files in an alternate mode directory.
void PrintPlugInfo(const base::FilePath& plug, int indent);

// GetPartnerProductType will look at the id_header VDO and USB PD revision to
// decode what type of device is being parsed.
ProductType GetPartnerProductType(const base::FilePath& dir);

// Similar to GetPartnerProductType, GetCableProductType will use the USB PD
// revision and id_header VDO to determine which type of cable is being used.
ProductType GetCableProductType(const base::FilePath& dir);

// PrintPartnerIdentity prints the contents of an identity directory including
// VDO fields which are determined by product type.
void PrintPartnerIdentity(const base::FilePath& partner, int indent);

// Similar to PrintPartnerIdentity, PrintCableIdentity will display the contents
// of the identity directory for a cable including VDO fields.
void PrintCableIdentity(const base::FilePath& cable, int indent);

// PrintPartner will print the immediate information in the partner directory,
// then print the identity and alternate mode information.
void PrintPartner(const base::FilePath& port, int indent);

// PrintCable will print the immediate information in the cable directory,
// then print the identity and alternate mode information.
void PrintCable(const base::FilePath& port, int indent);

// PrintPortInfo will print relevant type-c connector class information for the
// port located at the sysfs path "port"
void PrintPortInfo(const base::FilePath& port, int indent);

}  // namespace typec_connector_class_helper
}  // namespace debugd

#endif  // DEBUGD_SRC_HELPERS_TYPEC_CONNECTOR_CLASS_HELPER_UTILS_H_
