// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_G2F_TOOLS_G2F_CLIENT_H_
#define U2FD_G2F_TOOLS_G2F_CLIENT_H_

#include <cstdint>
#include <optional>
#include <string>

#include <brillo/secure_blob.h>
#include <hidapi/hidapi.h>

#include "u2fd/u2fhid.h"

namespace g2f_client {

struct FrameBlob;

// Represents the HID layer of a U2F HID device.
class HidDevice {
 public:
  // Channel ID, as specifid in section 2.4 of FIDO U2F HID Spec.
  struct Cid {
    uint8_t raw[4];

    constexpr uint32_t value() const {
      // Cid is stored in little endian byte order.
      // Note: Cid address may be unaligned, so can't use ntohl.
      return static_cast<uint32_t>(raw[0]) |
             (static_cast<uint32_t>(raw[1]) << 8) |
             (static_cast<uint32_t>(raw[2]) << 16) |
             (static_cast<uint32_t>(raw[3]) << 24);
    }
    constexpr uint32_t IsBroadcast() const { return value() == 0xFFFFFFFFu; }
  } __attribute__((__packed__));
  static_assert(sizeof(Cid) == 4, "Wrong Cid size");

  // Broadcast Channel ID, used during INIT command to create a channel.
  static constexpr Cid kCidBroadcast = {{0xFF, 0xFF, 0xFF, 0xFF}};

  // Creates a new instance for the device at the specified path.
  // Does not open the device.
  explicit HidDevice(const std::string& path);
  virtual ~HidDevice();

  virtual bool IsOpened() const { return dev_ != nullptr; }
  // Attempts to open the device, returns true on success.
  virtual bool Open();
  // Closes the device, if open.
  virtual void Close();
  // Sends a message to the given channel, with the specified command
  // and payload. Payload will be split into multiple messages if necessary.
  // Returns true on success.
  virtual bool SendRequest(const Cid& cid,
                           uint8_t cmd,
                           const brillo::Blob& payload);
  // Reads a response for the given channel. This should follow a call
  // to SendRequest. Returns true on success, false if a packet could
  // not be read, or an unexpected packet was read.
  virtual bool RecvResponse(const Cid& cid,
                            uint8_t* cmd,
                            brillo::Blob* payload,
                            int timeout_ms);

 private:
  bool WriteBlob(const FrameBlob& blob);
  bool ReadBlob(FrameBlob* blob, int timeout_ms);
  // Returns true if res == expected, prints out an error message and
  // returns false otherwise.
  bool CheckDeviceError(const std::string& func, int res, int expected);

  // Non-null iff the device is open.
  hid_device* dev_ = nullptr;
  // Path to the device.
  std::string path_;
};

// Represents U2F layer of a U2F HID device.
class U2FHid {
 public:
  using CommandCode = u2f::U2fHid::U2fHidCommand;
  using ErrorCode = u2f::U2fHid::U2fHidError;

  // Represents a U2F command, e.g. REGISTER or AUTHENTICATE.
  struct Command {
    uint8_t cmd;
    brillo::Blob payload;

    Command() = default;
    Command(CommandCode code, const brillo::Blob& payload)
        : cmd(static_cast<uint8_t>(code)), payload(payload) {}

    constexpr bool IsError() const {
      return cmd == static_cast<uint8_t>(CommandCode::kError);
    }
    constexpr uint8_t ErrorCode() const;
    // Returns true if the command was succesful, and prints
    // an error message if not.
    bool CheckSuccess(const std::string& descr) const;
    // Returns a description of the command.
    std::string Description() const;
    // Returns a hex-encoded dump of the command payload.
    std::string FullDump() const;
    // Returns a human-readable name for the command.
    std::string CommandName() const;
    // Returns a human-readable name for the error.
    std::string ErrorName() const;
  };

  // U2F HID Device version information, returned as part of
  // Init command.
  struct Version {
    uint8_t protocol;
    uint8_t major;
    uint8_t minor;
    uint8_t build;
  };

  // Creates a new instance for the specified hid_device, which must
  // outlive this instance.
  explicit U2FHid(HidDevice* hid_device);
  virtual ~U2FHid() = default;

  // Sends a raw Command and retrieves the response. Returns
  // true on success.
  bool RawCommand(const Command& request, Command* response);
  // Creates a new U2F HID Channel if necessary. Must be called
  // before calling any other commands below. If force_realloc is
  // true then a new channel will be created even if one already
  // exists. This sends a U2FHID_INIT command.
  bool Init(bool force_realloc);
  // Locks the device so that it only accepts commands from the
  // most recently created channel for the specified time.
  // This sends a U2FHID_LOCK command.
  bool Lock(uint8_t lock_timeout_seconds);
  // This sends the specified message to the device. The message
  // should be formatted according to section 4.1.1 of the FIDO
  // U2F HID spec. This sends a U2FHID_MSG command.
  virtual bool Msg(const brillo::Blob& request, brillo::Blob* response);
  // This sends a ping of the specified size to the device.
  // This is a U2FHID_PING command.
  bool Ping(size_t size);
  // This sends a U2FHID_WINK command, causing the device to
  // blink (or similar).
  bool Wink();

  // Returns true if a channel has been created, and the device
  // is ready to send commands (other than Init).
  bool Initialized() const { return !cid_.IsBroadcast(); }
  // Returns the device version information, provided by the
  // device during initialization. Must successfully call Init()
  // for this to be valid.
  const Version& GetVersion() const { return version_; }
  // Returns device capabilities, provided by the device during
  // initialization. Must successfully call Init() for this to be
  // valid. Capabilities format is specified in section 4.1.2 of
  // the FIDO U2FHID spec.
  uint8_t GetCaps() const { return caps_; }
  // Sets the channel ID to use (which must already exist).
  void SetCid(const HidDevice::Cid& cid) { cid_ = cid; }

 private:
  bool GetSuccessfulResponse(const Command& request, Command* response);

  HidDevice* hid_device_;
  HidDevice::Cid cid_ = HidDevice::kCidBroadcast;
  int timeout_ms_ = -1;
  Version version_;
  uint8_t caps_;
};

// Represents the U2F layer, responsible for sending
// register, authenticate, etc messages.
class U2F {
 public:
  // Creates a new instance to wrap the specified
  // u2f_device, which must outlive this instance.
  explicit U2F(U2FHid* u2f_device) : u2f_device_(u2f_device) {}

  // This sends a U2F_REGISTER message.
  bool Register(std::optional<uint8_t> p1,
                const brillo::Blob& challenge,
                const brillo::Blob& application,
                bool use_g2f_att_key,
                brillo::Blob* public_key,
                brillo::Blob* key_handle,
                brillo::Blob* certificate_and_signature);
  // This sends a U2F_AUTHENTICATE message.
  bool Authenticate(std::optional<uint8_t> p1,
                    const brillo::Blob& challenge,
                    const brillo::Blob& application,
                    const brillo::Blob& key_handle,
                    bool* presence_verified,
                    brillo::Blob* counter,
                    brillo::Blob* signature);

  static void AppendBlob(const brillo::Blob& from, brillo::Blob* to);

 private:
  // Sends a U2F message, checks that the response is sufficiently
  // long, and that the returned status word is SW_NO_ERROR. The
  // size specified should not include the two SW1 and SW2 bytes.
  // Returns false if size or status conditions are not met.
  bool SendMsg(const brillo::Blob& request,
               int min_response_size,
               brillo::Blob* response);

  // Copies data from a blob and appends to the end of another.
  // Start position is specified by from_it, which is updated
  // to point to the next unread byte, allowing subsequent calls
  // to re-use the same iterator to read the next available bytes.
  // Returns false if the source blob did not have enough data to
  // copy the requested length, true otherwise.
  static bool AppendFromResponse(const brillo::Blob& from,
                                 brillo::Blob::iterator* from_it,
                                 size_t length,
                                 brillo::Blob* to);

  U2FHid* u2f_device_;

  // This is the minimum set of sizes necessary to successfully
  // parse the response into sections; this does not imply that
  // further parsing of individual sections (e.g. the certificate)
  // will succeed.
  static constexpr int kRegResponseMinSize =
      1 +   // Reserved Byte (legacy reasons)
      65 +  // User Public key
      1 +   // Key Handle Length
      1 +   // Key Handle (minimum)
      1;    // Certificate + signature (minimum)
  static constexpr int kRegResponseStartOffset = 1;
  static constexpr int kRegResponsePublicKeyLength = 65;

  // This size should be interpreted in the same way as
  // kRegResponseMinSize above.
  static constexpr int kAuthResponseMinSize = 1 +  // User presence
                                              4 +  // Counter
                                              1;   // Signature

  static constexpr int kAuthResponseCounterOffset = 1;
  static constexpr int kAuthResponseCounterLength = 4;
};

}  // namespace g2f_client

#endif  // U2FD_G2F_TOOLS_G2F_CLIENT_H_
