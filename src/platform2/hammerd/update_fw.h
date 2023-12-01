// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This file contains structures used to facilitate EC firmware updates
// over USB. Note that many contents in this file are copied from EC overlay,
// and it might be trickier to include them directly.
//
// The firmware update protocol consists of two phases: connection
// establishment and actual image transfer.
//
// Image transfer is done in 1K blocks. The host supplying the image
// encapsulates blocks in PDUs by prepending a header including the flash
// offset where the block is destined and its digest.
//
// The EC device responds to each PDU with a confirmation which is 1 byte
// response. Zero value means success, non zero value is the error code
// reported by EC.
//
// To establish the connection, the host sends a different PDU, which
// contains no data and is destined to offset 0. Receiving such a PDU
// signals the EC that the host intends to transfer a new image.
//
// The connection establishment response is described by the
// FirstResponsePdu structure below.

#ifndef HAMMERD_UPDATE_FW_H_
#define HAMMERD_UPDATE_FW_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>
#include <openssl/sha.h>

#include "hammerd/fmap_utils.h"
#include "hammerd/usb_utils.h"

namespace hammerd {

constexpr int kUpdateProtocolVersion = 6;
constexpr uint32_t kUpdateDoneCmd = 0xB007AB1E;
constexpr uint32_t kUpdateExtraCmd = 0xB007AB1F;
constexpr int kEntropySize = 32;

enum class FirstResponsePduHeaderType {
  kCR50 = 0,
  kCommon = 1,
};

enum class UpdateCommandResponseStatus : uint32_t {
  kSuccess = 0,
  kBadAddr = 1,
  kEraseFailure = 2,
  kDataError = 3,
  kWriteFailure = 4,
  kVerifyError = 5,
  kGenError = 6,
  kMallocError = 7,
  kRollbackError = 8,
  kRateLimitError = 9,
  kRwsigBusy = 10,
};

// The extra vendor subcommand.
enum class UpdateExtraCommand : uint16_t {
  kImmediateReset = 0,
  kJumpToRW = 1,
  kStayInRO = 2,
  kUnlockRW = 3,
  kUnlockRollback = 4,
  kInjectEntropy = 5,
  kPairChallenge = 6,
  kTouchpadInfo = 7,
  kTouchpadDebug = 8,
  kConsoleReadInit = 9,
  kConsoleReadNext = 10,
  kMaxValue = kConsoleReadNext
};
const char* ToString(UpdateExtraCommand subcommand);

enum class EcResponseStatus : uint8_t {
  kSuccess = 0,
  kInvalidCommand = 1,
  kError = 2,
  kInvalidParam = 3,
  kAccessDenied = 4,
  kInvalidResponse = 5,
  kInvalidVersion = 6,
  kInvalidChecksum = 7,
  kInProgress = 8,         // Accepted, command in progress
  kUnavailable = 9,        // No response available
  kTimeout = 10,           // We got a timeout
  kOverflow = 11,          // Table / data overflow
  kInvalidHeader = 12,     // Header contains invalid data
  kRequestTruncated = 13,  // Didn't get the entire request
  kResponseTooBig = 14,    // Response was too big to handle
  kBusError = 15,          // Communications bus error
  kBusy = 16,              // Up but too busy.  Should retry
};

// Flash protection masks.
// Defined at EC repository: include/ec_commands.h
enum class EcFlashProtect : uint32_t {
  kROAtBoot = 1 << 0,
  kRONow = 1 << 1,
  kAllNow = 1 << 2,
  kGpioAsserted = 1 << 3,
  kErrorStuck = 1 << 4,
  kErrorInconsistent = 1 << 5,
  kAllAtBoot = 1 << 6,
  kRWAtBoot = 1 << 7,
  kRWNow = 1 << 8,
  kRollbackAtBoot = 1 << 9,
  kRollbackNow = 1 << 10,
};

// This is the frame format the host uses when sending update PDUs over USB.
//
// The PDUs are up to 1K bytes in size, they are fragmented into USB chunks of
// 64 bytes each and reassembled on the receive side before being passed to
// the flash update function.
//
// The flash update function receives the unframed PDU body, and puts its reply
// into the same buffer the PDU was in.
struct UpdateFrameHeader {
  uint32_t block_size;  // Total frame size, including this field.
  uint32_t block_digest;
  uint32_t block_base;
  UpdateFrameHeader() : UpdateFrameHeader(0, 0, 0) {}
  UpdateFrameHeader(uint32_t size, uint32_t digest, uint32_t base)
      : block_size(htobe32(size)),
        block_digest(htobe32(digest)),
        block_base(htobe32(base)) {}
};

// Response to the connection establishment request.
//
// When responding to the very first packet of the update sequence, the
// original USB update implementation was responding with a four byte value,
// just as to any other block of the transfer sequence.
//
// It became clear that there is a need to be able to enhance the update
// protocol, while staying backwards compatible.
//
// All newer protocol versions (starting with version 2) respond to the very
// first packet with an 8 byte or larger response, where the first 4 bytes are
// a version specific data, and the second 4 bytes - the protocol version
// number.
//
// This way the host receiving of a four byte value in response to the first
// packet is considered an indication of the target running the 'legacy'
// protocol, version 1. Receiving of an 8 byte or longer response would
// communicates the protocol version in the second 4 bytes.
struct FirstResponsePdu {
  uint32_t return_value;

  // The below fields are present in versions 2 and up.
  // Type of header following (one of first_response_pdu_header_type)
  uint16_t header_type;
  uint16_t protocol_version;  // Must be kUpdateProtocolVersion
  uint32_t maximum_pdu_size;  // Maximum PDU size
  uint32_t flash_protection;  // Flash protection status
  uint32_t offset;            // Offset of the other region
  char version[32];           // Version string of the other region
  int32_t min_rollback;       // Minimum rollback version that RO will accept
  uint32_t key_version;       // RO public key version
};

enum class SectionName { RO, RW, Invalid, kMaxValue = Invalid };
const char* ToString(SectionName name);
SectionName OtherSection(SectionName name);

// product_id format from elan_i2c.h. definition of ETP_PRODUCT_ID_FORMAT_STRING
constexpr char kElanFormatString[] = "%d.0";
constexpr uint8_t kElanBrokenFwVersion = 0xff;

constexpr char kStFormatString[] = "%d.%d";

const uint16_t ST_VENDOR_ID = 0x0483;
const uint16_t ELAN_VENDOR_ID = 0x04f3;

// Below is the touchpad_info struct from src/platform/ec/include/update_fw.h.
struct __attribute__((packed)) TouchpadInfo {
  uint8_t status;       // Indicate if we get info from touchpad
  uint8_t reserved;     // Reserved for padding
  uint16_t vendor;      // Vendor USB id
  uint32_t fw_address;  // Virtual address to touchpad firmware
  uint32_t fw_size;     // Size of the touchpad firmware
  // Checksum of the entire touchpad firmware accepted by the EC image
  uint8_t allowed_fw_hash[SHA256_DIGEST_LENGTH];
  union {
    struct {
      uint16_t id;
      uint16_t fw_version;
      uint16_t fw_checksum;
    } elan;
    struct {
      uint16_t id;
      uint16_t fw_version;
      uint16_t fw_checksum;
    } st;
  };
};

// The section information of the new EC image.
struct SectionInfo {
  SectionName name;
  uint32_t offset;
  uint32_t size;
  char version[32];
  int32_t rollback;
  int32_t key_version;
  explicit SectionInfo(SectionName name);
  SectionInfo(SectionName name,
              uint32_t offset,
              uint32_t size,
              const char* version,
              int32_t rollback,
              int32_t key_version);
  friend bool operator==(const SectionInfo& lhs, const SectionInfo& rhs);
  friend bool operator!=(const SectionInfo& lhs, const SectionInfo& rhs);
};

class FirmwareUpdaterInterface {
 public:
  virtual ~FirmwareUpdaterInterface() = default;

  // Scans the new EC image and retrieve versions of RO and RW sections.
  virtual bool LoadEcImage(const std::string& ec_image) = 0;

  // Retrieves local touchpad firmware.
  virtual bool LoadTouchpadImage(const std::string& touchpad_image) = 0;

  virtual bool UsbSysfsExists() = 0;
  virtual UsbConnectStatus ConnectUsb() = 0;
  // Tries to connect to the USB endpoint during a period of time.
  virtual UsbConnectStatus TryConnectUsb() = 0;

  // Closes the connection to the USB endpoint.
  virtual void CloseUsb() = 0;

  // Setups the connection with the EC firmware by sending the first PDU.
  // Returns true if successfully setup the connection.
  virtual bool SendFirstPdu() = 0;

  // Indicates to hammer that transferal of EC/touchpad firmware has completed.
  // Upon receipt of this message the target state machine transitions into
  // the 'rx_idle' state. The host may send an extension command to reset the
  // target after this.
  virtual void SendDone() = 0;

  // Injects entropy into the hammer device.
  virtual bool InjectEntropy() = 0;

  // Sends the external command through USB. The format of the payload is:
  //   4 bytes      4 bytes         4 bytes       2 bytes      variable size
  // +-----------+--------------+---------------+-----------+------~~~-------+
  // + total size| block digest |    EXT_CMD    | Vend. sub.|      data      |
  // +-----------+--------------+---------------+-----------+------~~~-------+
  //
  // Where 'Vend. sub' is the vendor subcommand, and data field is subcommand
  // dependent. The target tells between update PDUs and encapsulated vendor
  // subcommands by looking at the EXT_CMD value - it is kUpdateExtraCmd and
  // as such is guaranteed not to be a valid update PDU destination address.
  virtual bool SendSubcommand(UpdateExtraCommand subcommand) = 0;
  virtual bool SendSubcommandWithPayload(UpdateExtraCommand subcommand,
                                         const std::string& cmd_body) = 0;
  virtual bool SendSubcommandReceiveResponse(UpdateExtraCommand subcommand,
                                             const std::string& cmd_body,
                                             void* resp,
                                             size_t resp_size,
                                             bool allow_less = false) = 0;

  // Transfers the image to the target section.
  virtual bool TransferImage(SectionName section_name) = 0;

  // Transfers the touchpad firmware to a virtual address.
  virtual bool TransferTouchpadFirmware(uint32_t section_addr,
                                        size_t data_len) = 0;

  // Returns the current section that EC is running. One of "RO" or "RW".
  virtual SectionName CurrentSection() const = 0;

  // Returns whether the key version of the local image is valid
  // (i.e. matches key version in RW section of EC).
  virtual bool ValidKey() const = 0;

  // Compare the rollback version of the local image with current EC. Following
  // comparator function convention, it returns:
  //   0 if the rollback is equal to current EC
  //   1 if the rollback is higher than current EC (i.e. security update)
  //   -1 if the rollback is lower than current EC (i.e. disallow update)
  virtual int CompareRollback() const = 0;

  // Determines whether the given section has a different firmware version
  // from that of the local file.
  virtual bool VersionMismatch(SectionName section_name) const = 0;

  // Determines the section is locked or not.
  virtual bool IsSectionLocked(SectionName section_name) const = 0;

  // Determines whether the local image is considered a "critical" update.
  // IsCritical() == true must imply VersionMismatch(RW) == true.
  virtual bool IsCritical() const = 0;

  // Unlocks the section. Need to send "Reset" command afterward.
  virtual bool UnlockRW() = 0;

  // Determines the rollback is locked or not.
  virtual bool IsRollbackLocked() const = 0;

  // Unlocks the rollback. Need to send "Reset" command afterward.
  virtual bool UnlockRollback() = 0;

  virtual std::string GetEcImageVersion() const = 0;

  virtual std::string ReadConsole() = 0;
};

// Implement the core logic of updating firmware.
// It contains the data of the original transfer_descriptor.
class FirmwareUpdater : public FirmwareUpdaterInterface {
 public:
  explicit FirmwareUpdater(std::unique_ptr<UsbEndpointInterface> endpoint);

  // FirmwareUpdaterInterface implementation:
  bool LoadEcImage(const std::string& ec_image) override;
  bool LoadTouchpadImage(const std::string& touchpad_image) override;
  bool UsbSysfsExists() override;
  UsbConnectStatus ConnectUsb() override;
  UsbConnectStatus TryConnectUsb() override;
  void CloseUsb() override;
  bool SendFirstPdu() override;
  void SendDone() override;
  bool InjectEntropy() override;
  // InjectEntropyWithPayload is exposed at hammerd_api for FAFT use.
  // It should not be called directly in hammer_updater.
  bool InjectEntropyWithPayload(const std::string& payload);
  bool SendSubcommand(UpdateExtraCommand subcommand) override;
  bool SendSubcommandWithPayload(UpdateExtraCommand subcommand,
                                 const std::string& cmd_body) override;
  bool SendSubcommandReceiveResponse(UpdateExtraCommand subcommand,
                                     const std::string& cmd_body,
                                     void* resp,
                                     size_t resp_size,
                                     bool allow_less = false) override;
  bool TransferImage(SectionName section_name) override;
  bool TransferTouchpadFirmware(uint32_t section_addr,
                                size_t data_len) override;
  SectionName CurrentSection() const override;
  bool ValidKey() const override;
  int CompareRollback() const override;
  bool VersionMismatch(SectionName section_name) const override;
  bool IsSectionLocked(SectionName section_name) const override;
  bool IsCritical() const override;
  bool UnlockRW() override;

  bool IsRollbackLocked() const override;
  bool UnlockRollback() override;

  std::string GetEcImageVersion() const override;
  std::string ReadConsole() override;
  const FirstResponsePdu* GetFirstResponsePdu() const;
  std::string GetSectionVersion(SectionName section_name) const;

 protected:
  // Used in unit tests to inject mocks.
  FirmwareUpdater(std::unique_ptr<UsbEndpointInterface> endpoint,
                  std::unique_ptr<FmapInterface> fmap);
  FirmwareUpdater(const FirmwareUpdater&) = delete;
  FirmwareUpdater& operator=(const FirmwareUpdater&) = delete;

  // Fetches the version of the currently-running section.
  bool FetchVersion();

  // Transfers the data of the target section.
  bool TransferSection(const uint8_t* data_ptr,
                       uint32_t section_addr,
                       size_t data_len,
                       bool use_block_skip);

  // Transfers a block of data.
  bool TransferBlock(UpdateFrameHeader* ufh,
                     const uint8_t* transfer_data_ptr,
                     size_t payload_size,
                     bool use_block_skip);

  // The USB endpoint interface to the hammer EC.
  std::unique_ptr<UsbEndpointInterface> endpoint_;
  // The fmap function interface.
  std::unique_ptr<FmapInterface> fmap_;
  // The information of the first response PDU.
  FirstResponsePdu targ_;
  // The version of the currently-running section.  Retrieved through USB
  // endpoint's configuration string descriptor as part of TryConnectUsb.
  std::string version_;
  // The EC image data to be updated.
  std::string ec_image_;
  // The touchpad image data to be updated.
  std::string touchpad_image_;
  // The information of the RO and RW sections in the EC image data.
  std::vector<SectionInfo> sections_;

  friend class FirmwareUpdaterTest;
  FRIEND_TEST(FirmwareUpdaterTest, LoadEcImage);
  FRIEND_TEST(FirmwareUpdaterTest, TryConnectUsb_OK);
  FRIEND_TEST(FirmwareUpdaterTest, TryConnectUsb_FAIL);
  FRIEND_TEST(FirmwareUpdaterTest, TryConnectUsb_FetchVersion_Legacy);
  FRIEND_TEST(FirmwareUpdaterTest, TryConnectUsb_FetchVersion_FAIL);
  FRIEND_TEST(FirmwareUpdaterTest, SendDone);
  FRIEND_TEST(FirmwareUpdaterTest, SendFirstPdu);
  FRIEND_TEST(FirmwareUpdaterTest, SendFirstPdu_RwsigBusy);
  FRIEND_TEST(FirmwareUpdaterTest, SendSubcommand_InjectEntropy);
  FRIEND_TEST(FirmwareUpdaterTest, SendSubcommand_Reset);
  FRIEND_TEST(FirmwareUpdaterTest, TransferImage);
  FRIEND_TEST(FirmwareUpdaterTest, CurrentSection);
  FRIEND_TEST(FirmwareUpdaterTest, CheckKeyRollback);
  FRIEND_TEST(FirmwareUpdaterTest, VersionMismatch);
  FRIEND_TEST(FirmwareUpdaterTest, IsCritical);

 private:
  bool CheckEmptyBlock(const uint8_t* transfer_data_ptr, size_t payload_size);
};

}  // namespace hammerd
#endif  // HAMMERD_UPDATE_FW_H_
