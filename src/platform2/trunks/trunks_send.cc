// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>

#include <iterator>

#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/sys_byteorder.h>
#include <brillo/syslog_logging.h>
#include <crypto/sha2.h>
#include <libhwsec-foundation/tpm_error/tpm_error_uma_reporter.h>
#include <openssl/sha.h>

#include "trunks/trunks_dbus_proxy.h"

namespace {

using trunks::TrunksDBusProxy;

// Commands we support
constexpr char kForce[] = "force";
constexpr char kGetLock[] = "get_lock";
constexpr char kPopLogEntry[] = "pop_logentry";
constexpr char kRaw[] = "raw";
constexpr char kSetLock[] = "set_lock";
constexpr char kSysInfo[] = "sysinfo";
constexpr char kUpdate[] = "update";
constexpr char kU2fCert[] = "u2f_cert";
constexpr char kVerbose[] = "verbose";

// Maximum image update block size expected by GSC.
// Equals to SIGNED_TRANSFER_SIZE in src/platform/ec/chip/g/update_fw.h
static const uint32_t kTransferSize = 1024;

static int verbose;

void PrintUsage() {
  printf("Usage:\n");
  printf("  trunks_send --%s\n", kGetLock);
  printf("  trunks_send --%s\n", kSetLock);
  printf("  trunks_send --%s\n", kSysInfo);
  printf("  trunks_send --%s\n", kPopLogEntry);
  printf("  trunks_send --%s XX [XX ..]\n", kRaw);
  printf("  trunks_send [--%s] --%s <bin file>\n", kForce, kUpdate);
  printf("  trunks_send --%s [--crt=<file>] [--nonce=<txt>] [--appid=<txt>]\n",
         kU2fCert);
  printf("Options:\n");
  printf("   --%s\n", kVerbose);
}

std::string HexEncode(const std::string& bytes) {
  return base::HexEncode(bytes.data(), bytes.size());
}

// All TPM extension commands use this struct for input and output. Any other
// data follows immediately after. All values are big-endian over the wire.
struct TpmCmdHeader {
  uint16_t tag;              // TPM_ST_NO_SESSIONS
  uint32_t size;             // including this header
  uint32_t code;             // Command out, Response back.
  uint16_t subcommand_code;  // Additional command/response codes
} __attribute__((packed));

// TPMv2 Spec mandates that vendor-specific command codes have bit 29 set,
// while bits 15-0 indicate the command. All other bits should be zero. We
// define one of those 16-bit command values for GSC purposes, and use the
// subcommand_code in struct TpmCmdHeader to further distinguish the desired
// operation.
#define TPM_CC_VENDOR_BIT 0x20000000

// Vendor-specific command codes
#define TPM_CC_VENDOR_CR50 0x0000

// This needs to be used to be backwards compatible with older Cr50 versions.
#define CR50_EXTENSION_COMMAND 0xbaccd00a
#define CR50_EXTENSION_FW_UPGRADE 4

// GSC vendor-specific subcommand codes. 16 bits available.
enum vendor_cmd_cc {
  VENDOR_CC_POST_RESET = 7,
  VENDOR_CC_GET_LOCK = 16,
  VENDOR_CC_SET_LOCK = 17,
  VENDOR_CC_SYSINFO = 18,
  VENDOR_CC_U2F_APDU = 27,
  VENDOR_CC_POP_LOG_ENTRY = 28,
};

// The TPM response code is all zero for success.
// Errors are a little complicated:
//
//   Bits 31:12 must be zero.
//
//   Bit 11     S=0   Error
//   Bit 10     T=1   Vendor defined response code
//   Bit  9     r=0   reserved
//   Bit  8     V=1   Conforms to TPMv2 spec
//   Bit  7     F=0   Conforms to Table 14, Format-Zero Response Codes
//   Bits 6:0   num   128 possible failure reasons
#define VENDOR_RC_ERR 0x00000500
#define VENDOR_RC_MASK 0x0000007f
#define VENDOR_RC_NO_SUCH_COMMAND 0x0000007f

}  // namespace

// Send raw, unformatted bytes
static int HandleRaw(TrunksDBusProxy* proxy, base::CommandLine* cl) {
  std::string commandline;
  for (std::string arg : cl->GetArgs()) {
    commandline.append(arg);
  }
  base::RemoveChars(commandline, " \t\r\n:.", &commandline);

  std::vector<uint8_t> bytes;
  if (!base::HexStringToBytes(commandline, &bytes)) {
    LOG(ERROR) << "Can't convert input to bytes.";
    return 1;
  }

  std::string command(bytes.data(), bytes.data() + bytes.size());
  if (verbose) {
    printf("Out(%zd): ", command.size());
    puts(HexEncode(command).c_str());
  }
  std::string response = proxy->SendCommandAndWait(command);
  if (verbose) {
    printf("In(%zd):  ", response.size());
  }

  // Just print the result
  puts(HexEncode(response).c_str());

  return 0;
}

// Send the TPM command, get the reply, return response code and results.
static uint32_t VendorCommand(TrunksDBusProxy* proxy,
                              uint16_t cc,
                              const std::string& input,
                              std::string* output,
                              bool extendedCommandMode = false) {
  // Pack up the header and the input
  struct TpmCmdHeader header;
  header.tag = base::HostToNet16(trunks::TPM_ST_NO_SESSIONS);
  header.size = base::HostToNet32(sizeof(header) + input.size());
  if (extendedCommandMode)
    header.code = base::HostToNet32(CR50_EXTENSION_COMMAND);
  else
    header.code = base::HostToNet32(TPM_CC_VENDOR_BIT | TPM_CC_VENDOR_CR50);
  header.subcommand_code = base::HostToNet16(cc);

  std::string command(reinterpret_cast<char*>(&header), sizeof(header));
  command += input;

  // Send the command, get the response
  if (verbose) {
    printf("Out(%zd): ", command.size());
    puts(HexEncode(command).c_str());
  }
  std::string response = proxy->SendCommandAndWait(command);
  if (verbose) {
    printf("In(%zd):  ", response.size());
    puts(HexEncode(response).c_str());
  }

  if (response.size() < sizeof(header)) {
    LOG(ERROR) << "TPM response was too short!";
    return -1;
  }

  // Unpack the response header and any output
  memcpy(&header, response.data(), sizeof(header));
  header.size = base::NetToHost32(header.size);
  header.code = base::NetToHost32(header.code);

  // Error of some sort?
  if (header.code) {
    if ((header.code & VENDOR_RC_ERR) == VENDOR_RC_ERR) {
      fprintf(stderr, "TPM error code 0x%08x\n", header.code);
    }
  }

  // Pass back any reply beyond the header
  *output = response.substr(sizeof(header));

  return header.code;
}

//
// A convenience structure which allows to group together various revision
// fields of the header created by the signer.
//
// These fields are compared when deciding if versions of two images are the
// same or when deciding which one of the available images to run.
//
// Originally defined in src/platform/ec/chip/g/upgrade_fw.h
//
struct SignedHeaderVersion {
  uint32_t minor;
  uint32_t major;
  uint32_t epoch;
};

//
// Response to the connection establishment request.
//
// All protocol versions starting with version 2 respond to the very first
// packet with an 8 byte or larger response, where the first 4 bytes are a
// version specific data, and the second 4 bytes - the protocol version
// number.
//
// Originally defined in src/platform/ec/chip/g/upgrade_fw.h
//
struct FirstResponsePdu {
  uint32_t return_value;

  // The below fields are present in versions 2 and up.
  uint32_t protocol_version;

  // The below fields are present in versions 3 and up.
  uint32_t backup_ro_offset;
  uint32_t backup_rw_offset;

  // The below fields are present in versions 4 and up.
  // Versions of the currently active RO and RW sections.
  SignedHeaderVersion shv[2];

  // The below fields are present in versions 5 and up
  // keyids of the currently active RO and RW sections.
  uint32_t keyid[2];
};

struct UpdatePduHeader {
  uint32_t pdu_digest;
  uint32_t pdu_base_offset;
};

//
// GSC image header.
//
// Based on SignedHeader defined in src/platform/ec/chip/g/signed_header.h
//
struct EssentialHeader {
  uint32_t magic;
  uint32_t padding0[201];
  uint32_t image_size;
  uint32_t padding1[12];
  uint32_t epoch;
  uint32_t major;
  uint32_t minor;
};

//
// Wraps a block of image into a Vendor Command PDU and sends it to the device.
//
// Wrapping includes creating a header containing the digest of the entire PDU
// and the offset to program the PDU contents int the device's flash.
//
// |data| points to the entire firmware image containing RO and RW sections.
// |data_offset| is the offset into the image and into the flash memory, and
// |block_size| is the number of bytes to be tranferred with this block.
//
// Returns true on success, false on error.
//
static bool TransferBlock(TrunksDBusProxy* proxy,
                          const char* data,
                          size_t data_offset,
                          size_t block_size) {
  uint8_t digest[SHA_DIGEST_LENGTH];
  UpdatePduHeader updu;
  SHA_CTX shaCtx;
  std::string response;

  printf("sending 0x%zx bytes to offset %#zx\n", block_size, data_offset);

  updu.pdu_base_offset = base::NetToHost32(data_offset);
  SHA1_Init(&shaCtx);
  SHA1_Update(&shaCtx, &updu.pdu_base_offset, sizeof(updu.pdu_base_offset));
  SHA1_Update(&shaCtx, data + data_offset, block_size);
  SHA1_Final(digest, &shaCtx);

  memcpy(&updu.pdu_digest, digest, sizeof(updu.pdu_digest));

  std::string request =
      std::string(reinterpret_cast<char*>(&updu), sizeof(updu)) +
      std::string(data + data_offset, block_size);

  uint32_t rv =
      VendorCommand(proxy, CR50_EXTENSION_FW_UPGRADE, request, &response, true);
  if (rv) {
    LOG(ERROR) << "Failed to transfer image block, got 0x" << std::hex << rv;
    return false;
  }

  if (response.size() != 1) {
    LOG(ERROR) << "Unexpected return size " << response.size();
    return false;
  }

  if (response.data()[0]) {
    rv = response.data()[0];
    LOG(ERROR) << "Error " << rv;
    return false;
  }

  return true;
}

//
// Sends to the TPM the first transfer PDU, it is just 8 bytes of zeros. Verify
// the expected response (which is of FirstResponsePdu structure).
//
// Returns true on success, false on error.
//
static bool SetupConnection(TrunksDBusProxy* proxy, FirstResponsePdu* rpdu) {
  // Connection setup is triggered by 8 bytes of zeros.
  std::string request(8, 0);
  std::string response;

  uint32_t rv =
      VendorCommand(proxy, CR50_EXTENSION_FW_UPGRADE, request, &response, true);
  if (rv) {
    LOG(ERROR) << "Failed to set up connection, got 0x" << std::hex << rv;
    return false;
  }

  // We got something. Check for errors.
  if (response.size() < sizeof(FirstResponsePdu)) {
    LOG(ERROR) << "Unexpected response size " << response.size();
    return false;
  }

  // Let's unmarshal the response
  memcpy(rpdu, response.data(), std::min(sizeof(*rpdu), response.size()));

  rpdu->return_value = base::NetToHost32(rpdu->return_value);
  if (rpdu->return_value) {
    LOG(ERROR) << "Target reporting error 0x" << std::hex << rpdu->return_value;
    return false;
  }

  rpdu->protocol_version = base::NetToHost32(rpdu->protocol_version);
  if (rpdu->protocol_version < 5) {
    LOG(ERROR) << "Unsupported protocol version " << rpdu->protocol_version;
    return false;
  }
  printf("protocol version: %d\n", rpdu->protocol_version);
  rpdu->backup_ro_offset = base::NetToHost32(rpdu->backup_ro_offset);
  rpdu->backup_rw_offset = base::NetToHost32(rpdu->backup_rw_offset);

  for (int i = 0; i < std::size(rpdu->shv); i++) {
    rpdu->shv[i].minor = base::NetToHost32(rpdu->shv[i].minor);
    rpdu->shv[i].major = base::NetToHost32(rpdu->shv[i].major);
    rpdu->shv[i].epoch = base::NetToHost32(rpdu->shv[i].epoch);
  }

  printf("offsets: backup RO at %#x, backup RW at %#x\n",
         rpdu->backup_ro_offset, rpdu->backup_rw_offset);
  return true;
}

//
// Compares version fields in the header of the new image to the versions
// running on the target. Returns true if the new image is newer.
//
static bool ImageIsNewer(const EssentialHeader& header,
                         const SignedHeaderVersion& shv) {
  if (header.epoch != shv.epoch)
    return header.epoch > shv.epoch;
  if (header.major != shv.major)
    return header.major > shv.major;
  return header.minor > shv.minor;
}

//
// Updates RO or RW section of the GSC image on the device.
// A section is updated only if it's newer than the one currently on the
// device, or if |force| is set to true.
//
// |update_image| is the entire 512K file produced by the builder,
// |section_offset| is the offset of either inactive RO or inactive RW on
// the device, |shv| communicates this section's version retrieved from the
// device.
//
// Returns true on success, false on error. Skipping an update if the current
// version is not older than the one in |update_image| is considered a success.
//
static bool TransferSection(TrunksDBusProxy* proxy,
                            const std::string& update_image,
                            uint32_t section_offset,
                            const SignedHeaderVersion& shv,
                            bool force) {
  EssentialHeader header;

  // Try reading the header into the structure.
  if ((section_offset + sizeof(EssentialHeader)) > update_image.size()) {
    LOG(ERROR) << "Header at offset 0x" << std::hex << section_offset
               << " does not fit into the image of " << std::dec
               << update_image.size() << " bytes";
    return false;
  }
  memcpy(&header, update_image.data() + section_offset, sizeof(header));

  if (header.magic != 0xffffffff) {
    LOG(ERROR) << "Wrong magic value 0x" << std::hex << header.magic
               << " at offset 0x" << std::hex << section_offset;
    return false;
  }

  if (header.image_size > (update_image.size() - section_offset)) {
    LOG(ERROR) << "Wrong section size 0x" << std::hex << header.image_size
               << " at offset 0x" << std::hex << section_offset;
    return false;
  }

  printf("Offset %#x file at %d.%d.%d device at %d.%d.%d, section size %d\n",
         section_offset, header.epoch, header.major, header.minor, shv.epoch,
         shv.major, shv.minor, header.image_size);
  if (!force && !ImageIsNewer(header, shv)) {
    printf("Skipping update\n");
    return true;
  }

  // Transfer section, one block at a time.
  size_t block_size;
  for (uint32_t transferred = 0; transferred < header.image_size;
       transferred += block_size) {
    block_size = std::min(header.image_size - transferred, kTransferSize);
    if (!TransferBlock(proxy, update_image.data(), section_offset + transferred,
                       block_size)) {
      return false;
    }
  }

  return true;
}

//
// Updates the GSC image on the device. |update_image| contains the entire
// new GSC image.
// Each of the GSC sections is updated only if it's newer than the one
// currently on the device, or if |force| is set to true. Otherwise the
// session is skipped. The information about the section offsets and current
// versions is taken from the response to the connection request |rpdu| received
// from the device earlier.
//
// Returns the number of successfully updated sections (including skipped), or
// a negative value in case of error.
//
static int TransferImage(TrunksDBusProxy* proxy,
                         const std::string& update_image,
                         const FirstResponsePdu& rpdu,
                         bool force) {
  int num_txed_sections = 0;
  uint32_t section_offsets[] = {rpdu.backup_ro_offset, rpdu.backup_rw_offset};
  int index;

  //
  // The GSC will not accept lower addresses after higher addresses for 60
  // seconds. Decide what section needs to be transferred first.
  //

  index = section_offsets[0] > section_offsets[1] ? 1 : 0;
  for (int i = 0; i < std::size(section_offsets); i++) {
    if (!TransferSection(proxy, update_image, section_offsets[index],
                         rpdu.shv[index], force)) {
      if (!force) {
        return -1;
      }
    } else {
      num_txed_sections++;
    }
    index = (index + 1) % std::size(section_offsets);
  }

  return num_txed_sections;
}

enum UpdateStatus { UpdateSuccess = 0, UpdateError = 1, UpdateCancelled = 2 };

// Update the GSC image on the device.
static UpdateStatus HandleUpdate(TrunksDBusProxy* proxy,
                                 base::CommandLine* cl) {
  if (cl->GetArgs().size() != 1) {
    LOG(ERROR) << "A single image file name must be provided.";
    return UpdateError;
  }

  base::FilePath filename(cl->GetArgs()[0]);

  std::string update_image;
  if (!base::ReadFileToString(filename, &update_image)) {
    LOG(ERROR) << "Failed to read " << filename.value();
    return UpdateError;
  }

  FirstResponsePdu rpdu;
  if (!SetupConnection(proxy, &rpdu)) {
    return UpdateError;
  }

  // Cr50 images with RW version below 0.0.19 process updates differently,
  // and as such require special treatment.
  bool running_pre_19 = rpdu.shv[1].minor < 19 && rpdu.shv[1].major == 0 &&
                        rpdu.shv[1].epoch == 0;

  if (running_pre_19 && !cl->HasSwitch(kForce)) {
    printf("Not updating from RW 0.0.%d, use --force if necessary\n",
           rpdu.shv[1].minor);
    return UpdateCancelled;
  }

  int rv = TransferImage(proxy, update_image, rpdu, cl->HasSwitch(kForce));

  if (rv < 0) {
    return UpdateError;
  }

  // Positive rv indicates that some sections were transferred and a GSC
  // reboot is required. RW Cr50 versions below 0.0.19 require a posted reset
  // to switch to the new image.
  if (rv > 0 && running_pre_19) {
    std::string dummy;

    LOG(INFO) << "Will post a reset request.";

    if (VendorCommand(proxy, VENDOR_CC_POST_RESET, dummy, &dummy, true)) {
      LOG(ERROR) << "Failed to post a reset request.";
      return UpdateError;
    }
  }

  return UpdateSuccess;
}

// Vendor command to get the console lock state
static int VcGetLock(TrunksDBusProxy* proxy, base::CommandLine* cl) {
  std::string out;
  uint32_t rc = VendorCommand(proxy, VENDOR_CC_GET_LOCK, out, &out);

  if (!rc)
    printf("lock is %s\n", out[0] ? "enabled" : "disabled");

  return rc != 0;
}

// Vendor command to set the console lock
static int VcSetLock(TrunksDBusProxy* proxy, base::CommandLine* cl) {
  std::string out;
  uint32_t rc = VendorCommand(proxy, VENDOR_CC_SET_LOCK, out, &out);

  if (!rc)
    printf("lock is enabled\n");

  return rc != 0;
}

static const char* key_type(uint32_t key_id) {
  // It is a mere convention, but all prod keys are required to have key
  // IDs such that bit D2 is set, and all dev keys are required to have
  // key IDs such that bit D2 is not set.
  if (key_id & (1 << 2))
    return "prod";
  else
    return "dev";
}

// SysInfo command:
// There are no input args.
// Output is this struct, all fields in network order.
struct sysinfo_s {
  uint32_t ro_keyid;
  uint32_t rw_keyid;
  uint32_t dev_id0;
  uint32_t dev_id1;
} __attribute__((packed));

static int VcSysInfo(TrunksDBusProxy* proxy, base::CommandLine* cl) {
  std::string out;
  uint32_t rc = VendorCommand(proxy, VENDOR_CC_SYSINFO, out, &out);

  if (rc)
    return 1;

  if (out.size() != sizeof(struct sysinfo_s)) {
    LOG(ERROR) << "Wrong TPM response size.";
    return 1;
  }

  struct sysinfo_s sysinfo;
  memcpy(&sysinfo, out.c_str(), out.size());
  sysinfo.ro_keyid = base::NetToHost32(sysinfo.ro_keyid);
  sysinfo.rw_keyid = base::NetToHost32(sysinfo.rw_keyid);
  sysinfo.dev_id0 = base::NetToHost32(sysinfo.dev_id0);
  sysinfo.dev_id1 = base::NetToHost32(sysinfo.dev_id1);

  printf("RO keyid:    0x%08x (%s)\n", sysinfo.ro_keyid,
         key_type(sysinfo.ro_keyid));
  printf("RW keyid:    0x%08x (%s)\n", sysinfo.rw_keyid,
         key_type(sysinfo.rw_keyid));
  printf("DEV_ID:      0x%08x 0x%08x\n", sysinfo.dev_id0, sysinfo.dev_id1);

  return 0;
}

// PopLogEntry command:
// There are no input args.
// Output is this struct, all fields in network order.
struct logentry_s {
  uint32_t timestamp; /* Relative timestamp of event, "msec ago" */
  uint8_t type;       /* Type of event logged */
  uint8_t size;       /* Byte size of extra payload data, only 0 supported */
  uint16_t data;      /* Type-defined additional log info */
} __attribute__((packed));

static int VcPopLogEntry(TrunksDBusProxy* proxy, base::CommandLine* cl) {
  std::string out;
  uint32_t rc = VendorCommand(proxy, VENDOR_CC_POP_LOG_ENTRY, out, &out);
  base::Time ts;
  base::Time::Exploded ts_exploded;

  if (rc)
    return 1;

  if (out.size() == 0) {
    LOG(INFO) << "No log entry available.";
    return 0;
  }
  if (out.size() != sizeof(struct logentry_s)) { /* proper struct */
    LOG(ERROR) << "Wrong TPM response size.";
    return 1;
  }

  struct logentry_s logentry;
  memcpy(&logentry, out.c_str(), out.size());
  logentry.timestamp = base::NetToHost32(logentry.timestamp);
  logentry.data = base::NetToHost16(logentry.data);

  ts = base::Time::Now() - base::Milliseconds(logentry.timestamp);
  ts.LocalExplode(&ts_exploded);

  printf("LogEntry %04i%02i%02i-%02i:%02i:%02i.%03i: Type: 0x%x Data: 0x%x\n",
         ts_exploded.year, ts_exploded.month, ts_exploded.day_of_month,
         ts_exploded.hour, ts_exploded.minute, ts_exploded.second,
         ts_exploded.millisecond, logentry.type, logentry.data);
  return 0;
}

// U2F APDU header (as defined by ISO7816-4:2005)
struct ApduHeader {
  uint8_t cla;
  uint8_t ins;
  uint8_t p1;
  uint8_t p2;
  uint8_t lc;
} __attribute__((packed));

static int SendU2fApdu(TrunksDBusProxy* proxy,
                       uint8_t ins,
                       uint8_t p1,
                       uint8_t p2,
                       const std::string& payload,
                       std::string* response) {
  std::string out;
  struct ApduHeader apdu;

  // The instruction class is always 0 for this transport.
  apdu.cla = 0;
  apdu.ins = ins;
  apdu.p1 = p1;
  apdu.p2 = p2;
  // Record the size of the payload, only supports small sizes < 256 bytes.
  if (payload.size() > 255)
    return -EINVAL;
  apdu.lc = payload.size();

  std::string request =
      std::string(reinterpret_cast<char*>(&apdu), sizeof(apdu)) + payload;
  uint32_t rc = VendorCommand(proxy, VENDOR_CC_U2F_APDU, request, &out);
  if (!rc) {
    if (out.length() < sizeof(uint16_t))
      return -EINVAL;
    // The status word is stored in the last 2 bytes.
    size_t sw_off = out.length() - sizeof(uint16_t);
    uint16_t sw;
    memcpy(&sw, out.c_str() + sw_off, sizeof(sw));
    *response = out.substr(0, sw_off);
    return base::NetToHost16(sw);
  }
  return -rc;
}

// ECDSA P256 uses 256-bit integers.
#define P256_NBYTES (256 / 8)

static int VcU2fCert(TrunksDBusProxy* proxy, base::CommandLine* cl) {
  const uint8_t kCmdU2fRegister = 0x01;
  const uint8_t kCmdU2fVendorMode = 0xbf;
  const uint8_t kG2fAttest = 0x80;
  const uint8_t kSetMode = 1;
  const uint8_t kU2fExtended = 3;
  const uint16_t kSwNoError = 0x9000;

  std::string resp;

  // Send the mode to U2f + extensions
  int sw = SendU2fApdu(proxy, kCmdU2fVendorMode, kSetMode, kU2fExtended,
                       std::string(), &resp);
  if (sw < 0) {
    if ((-sw & VENDOR_RC_MASK) == VENDOR_RC_NO_SUCH_COMMAND)
      LOG(ERROR) << "U2F Feature not available in firmware.";
    else
      LOG(ERROR) << "U2F vendor command failed with error " << std::hex << -sw;
    return 1;
  } else if (sw != kSwNoError) {
    LOG(ERROR) << "Set U2F Mode failed SW=" << std::hex << sw;
    return 1;
  }
  if (resp.length() < 1 || resp[0] != kU2fExtended) {
    LOG(ERROR) << "Cannot set extended U2F Mode " << std::hex
               << static_cast<int>(resp[0]);
    return 1;
  }

  // Use the SHA-256 of the empty string if no parameter is passed.
  std::string nonce(crypto::SHA256HashString(cl->GetSwitchValueASCII("nonce")));
  std::string appid(crypto::SHA256HashString(cl->GetSwitchValueASCII("appid")));

  std::string payload = nonce + appid;
  sw = SendU2fApdu(proxy, kCmdU2fRegister, kG2fAttest, 0, payload, &resp);
  if (sw != kSwNoError) {
    LOG(ERROR) << "U2F Register failed  SW=" << std::hex << sw;
    return 1;
  }

  // The response is:
  // A reserved byte [1 byte], which for legacy reasons has the value 0x05.
  // A user public key [65 bytes]. This is the (uncompressed) x,y-representation
  //                               of a curve point on the P-256 elliptic curve.
  // A key handle length byte [1 byte], which specifies the length of the key
  //                                    handle (see below).
  //                                    The value is unsigned (range 0-255).
  // A key handle [length, see previous field]. This a handle that
  //                                    allows the U2F token to identify the
  //                                    generated key pair. U2F tokens may wrap
  //                                    the generated private key and the
  //                                    application id it was generated for,
  //                                    and output that as the key handle.
  // An attestation certificate [variable length]. This is a certificate in
  //                                    X.509 DER format.
  // A signature. This is a ECDSA signature (on P-256).
  const int pkey_offset = 1;
  const size_t pkey_size = 1 + 2 * P256_NBYTES;
  const int handle_len_offset = pkey_offset + pkey_size;
  const int handle_offset = handle_len_offset + 1;

  if (resp.size() < handle_offset) {  // Invalid response length
    LOG(ERROR) << "Invalid response length " << resp.size() << " < "
               << handle_offset;
    return 1;
  }
  printf("PubKey: %s\n",
         HexEncode(resp.substr(pkey_offset, pkey_size)).c_str());

  uint8_t handle_len = resp[handle_len_offset];
  if (resp.size() < handle_offset + handle_len) {  // Invalid response length
    LOG(ERROR) << "Invalid response length " << resp.size() << " < "
               << handle_offset << " + " << handle_len;
    return 1;
  }
  printf("KeyHandle: %s\n",
         HexEncode(resp.substr(handle_offset, handle_len)).c_str());
  const int cert_offset = handle_offset + handle_len;
  if (resp.size() < cert_offset + 4) {  // Invalid response length
    LOG(ERROR) << "Invalid response length " << resp.size() << " < "
               << handle_offset << " + 4";
    return 1;
  }
  // parse the first tag of the certificate ASN.1 data to know its length.
  std::string cert_seq_tag = resp.substr(cert_offset, 4);
  // If we cannot find the size, do a safe bet and use the P256 signature
  // uncompressed size while it is ASN.1 DER encoded here, the certificate
  // might have few trailing bytes from the signature which is harmless.
  size_t cert_size = resp.size() - cert_offset - P256_NBYTES;

  // ASN.1 DER constants we are using.
  static const uint8_t kAsn1ClassStructured = 0x20;
  static const uint8_t kAsn1TagSequence = 0x10;
  static const uint8_t kAsn1LengthLong = 0x80;
  // Should be a Constructed Sequence ASN.1 tag else all bets are off,
  // with the size taking 2 bytes (the certificate size is somewhere between
  // 256B and 2KB).
  if ((static_cast<uint8_t>(cert_seq_tag[0]) ==
       (kAsn1ClassStructured | kAsn1TagSequence)) &&
      (static_cast<uint8_t>(cert_seq_tag[1]) ==
       (kAsn1LengthLong | sizeof(uint16_t)))) {
    uint16_t length_tag;
    memcpy(&length_tag, cert_seq_tag.c_str() + 2, sizeof(length_tag));
    cert_size = base::NetToHost16(length_tag) + cert_seq_tag.size();
  }
  if (resp.size() < cert_offset + cert_size) {  // Invalid response length
    LOG(ERROR) << "Invalid response length " << resp.size() << " < "
               << cert_offset << " + " << cert_size;
    return 1;
  }

  std::string cert = resp.substr(cert_offset, cert_size);
  printf("Cert: %s\n", HexEncode(cert).c_str());
  const int sig_offset = cert_offset + cert_size;
  const size_t sig_size = resp.size() - sig_offset;
  if (resp.size() < sig_offset + sig_size) {  // Invalid response length
    LOG(ERROR) << "Invalid response length " << resp.size() << " < "
               << sig_offset << " + " << sig_size;
    return 1;
  }
  printf("Signature(P256): %s\n",
         HexEncode(resp.substr(sig_offset, sig_size)).c_str());

  base::FilePath crt(cl->GetSwitchValuePath("crt"));
  if (!crt.empty()) {
    printf("Certificate file: %s\n", crt.value().c_str());
    base::WriteFile(crt, cert.data(), cert.size());
  }

  return 0;
}

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToStderr);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  // Set TPM metrics client ID.
  hwsec_foundation::SetTpmMetricsClientID(
      hwsec_foundation::TpmMetricsClientID::kTrunksSend);

  if (cl->HasSwitch(kVerbose)) {
    verbose = 1;
  }

  TrunksDBusProxy proxy;
  if (!proxy.Init()) {
    LOG(ERROR) << "Failed to initialize dbus proxy.";
    return 1;
  }

  if (cl->HasSwitch(kRaw))
    return HandleRaw(&proxy, cl);

  if (cl->HasSwitch(kGetLock))
    return VcGetLock(&proxy, cl);

  if (cl->HasSwitch(kPopLogEntry))
    return VcPopLogEntry(&proxy, cl);

  if (cl->HasSwitch(kSetLock))
    return VcSetLock(&proxy, cl);

  if (cl->HasSwitch(kSysInfo))
    return VcSysInfo(&proxy, cl);

  if (cl->HasSwitch(kU2fCert))
    return VcU2fCert(&proxy, cl);

  if (cl->HasSwitch(kUpdate))
    return HandleUpdate(&proxy, cl);

  PrintUsage();
  return 1;
}
