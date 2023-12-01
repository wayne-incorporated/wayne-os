# U2Fd : U2FHID Emulation Daemon

## About

U2Fd (Universal Second Factor Daemon) is a daemon emulating a U2FHID interface
as defined by the FIDO Alliance [FIDO U2F HID Protocol Specification] and
forwarding the raw U2F APDU it has extracted (as defined by
[FIDO U2F Raw Message Formats]) to the actual U2F implementation.

It is used as part of the _Integrated_ _Second_ _Factor_ _Authentication_ in the
Chromebook where the U2F implementation is provided by the on-board security
chip firmware.

## Data flow

The U2Fd daemon creates a new HID device from userspace using the UHID kernel
interface and gets the U2F HID reports from there (as implemented by the
`UHidDevice` class).

The daemon parses the HID reports and re-constructs the U2FHID messages from the
succession of frames: one INIT and CONT (as implemented by the `U2fHid` class).
It answers the INIT and LOCK messages as expected by the protocol specification,
and when it gets a MSG message containing a U2F APDU as payload, it simply
forwards it to the provided `TransmitApduCallback` function.

In this implementation, the U2F APDUs are sent to the cr50 firmware in the TPM
security chip which has an extension to process U2F APDUs sent through a vendor
defined command.
The `TpmVendorCommandProxy` class encapsulates an APDU in the VENDOR_CC_U2F_APDU
vendor command and sends it to the trunks daemon using a D-Bus connection.
The latter communicates itself with the physical TPM through the kernel driver
exposing `/dev/tpm0`.

The HID interface created by the U2Fd daemon is used by the usual un-modified
security key clients (e.g. the Chrome browser through the permission broker).

## Physical Presence

The U2F firmware is using the laptop power button as the user physical presence
sensing.
In order to avoid spurious UI actions when the user touches the power button to
acknowledge their presence, the daemon scans the U2F requests and when it sees a
physical presence test, it temporarily de-activates the next power button press
forwarding to the UI (by sending a D-Bus message to powerd).

## Interfaces

The daemon has 3 interfaces to the outside world:

-   the `/dev/uhid` kernel node to create/communicate with the HID device.
-   a D-Bus proxy to the trunksd daemon to send TPM messages.
-   a D-Bus proxy to the powerd daemon to send power button
    overrides.

## Testing

The implementation can be tested on the laptop by using the [HIDTest] and
[U2FTest] [reference test programs].

[HIDTest] will also be converted to a unit-test for the `U2fHid` class.

## Firmware compatibility

To support versioned U2F key handles (used in WebAuthn), a cr50 firmware change
was introduced in milestone M87. This new firmware will not work with the U2Fd
daemon on older milestones. For example, if you update a device to M87 then downgrade
to M86, keys registered on M87 will not work, as the cr50 firmware will not roll back
to the M86 version. Registering new keys on M86 will not work either, because the M87
cr50 firmware expects a different u2f_register_req struct from M86. You need to get
the device back to M87 to use U2F keys.

## Specifications

The FIDO Alliance specifications:

-   [FIDO U2F HID Protocol Specification]
-   [FIDO U2F Raw Message Formats]

[FIDO U2F HID Protocol Specification]: https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-hid-protocol-v1.1-id-20160915.html
[FIDO U2F Raw Message Formats]: https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html
[reference test programs]: https://github.com/fido-alliance/google-u2f-ref-code/blob/HEAD/u2f-tests/
[HIDTest]: https://github.com/fido-alliance/google-u2f-ref-code/blob/HEAD/u2f-tests/HID/HIDTest.cc
[U2FTest]: https://github.com/fido-alliance/google-u2f-ref-code/blob/HEAD/u2f-tests/HID/U2FTest.cc
