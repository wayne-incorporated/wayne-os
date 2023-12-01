# The ChromiumOS Platform

This repo holds (most) of the custom code that makes up the ChromiumOS
platform.  That largely covers daemons, programs, and libraries that were
written specifically for ChromiumOS.

We moved from multiple separate repos in platform/ to a single repo in
platform2/ for a number of reasons:

* Make it easier to work across multiple projects simultaneously
* Increase code re-use (via common libs) rather than duplicate utility
  functions multiple items over
* Share the same build system

While most projects were merged, not all of them were.  Some projects were
standalone already (such as vboot), or never got around to being folded in
(such as imageloader).  Some day those extra projects might get merged in.

Similarly, some projects that were merged in, were then merged back out.
This was due to the evolution of the Brillo project and collaboration with
Android.  That means the AOSP repos are the upstream and ChromiumOS carries
copies.

# Local Project Directory

| Project | Description |
|---------|-------------|
| [arc](./arc/) | Tools/deamons/init-scripts to run ARC |
| [attestation](./attestation/) | Daemon and client for managing remote attestation |
| [authpolicy](./authpolicy/) | Daemon for integrating with Microsoft Active Directory (AD) domains |
| [avtest_label_detect](./avtest_label_detect/) | Test tool for OCRing device labels |
| [biod](./biod/) | Biometrics daemon |
| [bootid-logger](./bootid-logger/) | Simple command to record the current boot id to the log. |
| [bootlockbox](./bootlockbox/) | Daemon and client for boot lockbox service.|
| [bootstat](./bootstat/) | Tools for tracking points in the overall boot process (for metrics) |
| [camera](./camera/) | ChromeOS Camera daemon |
| [cecservice](./cecservice/) | Service for switching CEC enabled TVs on and off |
| [cfm-dfu-notification](./cfm-dfu-notification/) | CFM specific library for DFU notifications |
| [chaps](./chaps/) | PKCS #11 implementation for TPM 1 devices |
| [chargesplash](./chargesplash/) | Frecon-based charging indicator |
| [chromeos-common-script](./chromeos-common-script/) | Shared scripts for partitions and basic disk information |
| [chromeos-config](./chromeos-config/) | CrOS unified build runtime config manager |
| [chromeos-dbus-bindings](./chromeos-dbus-bindings/) | Simplifies the implementation of D-Bus daemons and proxies |
| [chromeos-nvt-tcon-updater](./chromeos-nvt-tcon-updater/) | Library for integrating the Novatek TCON firmware updater into a CrOS device |
| [codelab](./codelab/) | Codelab exercise |
| [common-mk](./common-mk/) | Common build & test logic for platform2 projects |
| [crash-reporter](./crash-reporter/) | The system crash handler & reporter |
| [cronista](./cronista/) | Tamper evident storage daemon |
| [cros-disks](./cros-disks/) | Daemon for mounting removable media (e.g. USB sticks and SD cards) |
| [crosdns](./crosdns/) | Hostname resolution service for ChromeOS |
| [crosh](./crosh/) | The ChromiumOS shell |
| [croslog](./croslog/) | The log manipulation command |
| [cryptohome](./cryptohome/) | Daemon and tools for managing encrypted /home and /var directories |
| [cups_proxy](./cups_proxy/) | Daemon for proxying CUPS printing request |
| [debugd](./debugd/) | Centralized debug daemon for random tools |
| [dev-install](./dev-install/) | Tools & settings for managing the developer environment on the device |
| [diagnostics](./diagnostics/) | Device telemetry and diagnostics daemons |
| [discod](./discod/) | Control Loop for behavioural storage devices features (e.g. UFS Write Booster) |
| [disk_updater](./disk_updater/) | Utility for updating root disk firmware (e.g. SSDs and eMMC) |
| [dlcservice](./dlcservice/) | Downloadable Content (DLC) Service daemon |
| [dlp](./dlp/) | Date Leak Prevention (DLP) daemon |
| [dns-proxy](./dns-proxy/) | DNS Proxy daemon |
| [easy-unlock](./easy-unlock/) | Daemon for handling Easy Unlock requests (e.g. unlocking Chromebooks with an Android device) |
| [enterprise](./enterprise/) | Daemon for handling enterprise related values |
| [faced](./faced/) | Face Authentication Daemon |
| [feature_usage](./feature_usage/) | Library to provide a unified approach to report feature usage events |
| [featured](./featured/) | Feature daemon for enabling and managing platform features |
| [federated](./federated/) | Federated computation service (Federated Analytics & Federated Learning) |
| [feedback](./feedback/) | Daemon for headless systems that want to gather feedback (normally Chrome manages it) |
| [flex_bluetooth](./flex_bluetooth/) | Updates Floss overrides for ChromeOS Flex |
| [flex_id](./flex_id/) | Utility for generating flex_id, a machine identifier for devices without VPD info |
| [foomatic_shell](./foomatic_shell/) | Simple shell used by the foomatic-rip package |
| [fusebox](./fusebox/) | FuseBox service |
| [glib-bridge](./glib-bridge/) | library for libchrome-glib message loop interoperation |
| [goldfishd](./goldfishd/) | Android Emulator Daemon |
| [hammerd](./hammerd/) | Firmware updater utility for hammer hardware |
| [hardware_verifier](./hardware_verifier/) | Hardware verifier tool |
| [hermes](./hermes/) | ChromeOS LPA implementation for eSIM hardware support |
| [hiberman](./hiberman/) | ChromeOS Hibernation Manager |
| [hps](./hps/) | ChromeOS HPS daemon and utilities |
| [hwsec-host-utils](./hwsec-host-utils/) | Hwsec-related host-only utilities |
| [hwsec-optee-plugin](./hwsec-optee-plugin/) | Hwsec-related optee plugin |
| [hwsec-optee-ta](./hwsec-optee-ta/) | Hwsec-related optee plugin trusted application |
| [hwsec-test-utils](./hwsec-test-utils/) | Hwsec-related test-only features |
| [hwsec-utils](./hwsec-utils/) | Hwsec-related features |
| [iioservice](./iioservice/) | Daemon and libraries that provide sensor data to all processes |
| [image-burner](./image-burner/) | Daemon for writing disk images (e.g. recovery) to USB sticks & SD cards |
| [imageloader](./imageloader/) | Daemon for mounting signed disk images |
| [init](./init/) | CrOS common startup init scripts and boot time helpers |
| [installer](./installer/) | CrOS installer utility (for AU/recovery/etc...) |
| [ippusb_bridge](./ippusb_bridge/) | HTTP proxy to IPP-enabled printers |
| [kerberos](./kerberos/) | Daemon for managing Kerberos tickets |
| [kexec-lite](./kexec-lite/) | Simple implementation of kexec-tools |
| [libarc-attestation](./libarc-attestation/) | Library to facilitate Android Attestation and Remote Key Provisioning for ARC Keymint Daemon |
| [libbrillo](./libbrillo/) | Common platform utility library |
| [libchromeos-rs](./libchromeos-rs/) | Common platform utility library for Rust |
| [libchromeos-ui](./libchromeos-ui/) ||
| [libcontainer](./libcontainer/) ||
| [libcrossystem](./libcrossystem/) | Library for getting ChromeOS system properties |
| [libec](./libec/) | Library for interacting with [EC](https://chromium.googlesource.com/chromiumos/platform/ec/) |
| [libhwsec](./libhwsec/) | Library for the utility functions of all TPM related daemons except for trunks and trousers |
| [libhwsec-foundation](./libhwsec-foundation/) | Library for the utility functions of all TPM related daemons and libraries |
| [libipp](./libipp/) | Library for building and parsing IPP (Internet Printing Protocol) frames |
| [libmems](./libmems/) | Utility library to configure, manage and retrieve events from IIO sensors |
| [libpasswordprovider](./libpasswordprovider/) | Password Provider library for securely managing credentials with system services |
| [libsar](./libsar/) | Utility library to read the config file of IIO Sar sensors |
| [libsegmentation](./libsegmentation/) | Library to check which software features are allowed |
| [login_manager](./login_manager/) | Session manager for handling the life cycle of the main session (e.g. Chrome) |
| [lorgnette](./lorgnette/) | Daemon for managing attached USB scanners via [SANE](https://en.wikipedia.org/wiki/Scanner_Access_Now_Easy) |
| [lvmd](./lvmd/) | ChromeOS LVM daemon |
| [media_capabilities](./media_capabilities/) | Command line tool to show video and camera capabilities |
| [media_perception](./media_perception/) | Media perception service for select platforms |
| [memd](./metrics/memd/) | Daemon that logs memory-related data and events |
| [mems_setup](./mems_setup/) | Boot-time initializer tool for sensors |
| [metrics](./metrics/) | Client side user metrics collection |
| [midis](./midis/) | [MIDI](https://en.wikipedia.org/wiki/MIDI) service |
| [minios](./minios/) | A minimal OS used during recovery |
| [missive](./missive/) | Daemon for the storage of encrypted records for managed devices. |
| [mist](./mist/) | Modem USB Interface Switching Tool |
| [ml](./ml/) | Machine learning service |
| [ml_benchmark](./ml_benchmark/) | ML performance benchmark for ChromeOS |
| [ml_core](./ml_core/) | Machine learning feature library |
| [modem-utilities](./modem-utilities/) ||
| [modemfwd](./modemfwd/) | Daemon for managing modem firmware updaters |
| [mojo_service_manager](./mojo_service_manager/) | Daemon for managing mojo services |
| [mtpd](./mtpd/) | Daemon for handling Media Transfer Protocol (MTP) with devices (e.g. phones) |
| [net-base](./net-base/) | library of networking primitive data structure and common utilities |
| [nnapi](./nnapi/) | Implementation of the Android [Neural Networks API](https://developer.android.com/ndk/guides/neuralnetworks) |
| [ocr](./ocr/) | Optical Character Recognition (OCR) service for ChromeOS |
| [oobe_config](./oobe_config/) | Utilities for saving and restoring OOBE config state |
| [os_install_service](./os_install_service/) | Service that can be triggered by the UI to install CrOS to disk from a USB device |
| [p2p](./p2p/) | Service for sharing files between CrOS devices (e.g. updates) |
| [parallax](./parallax/) | Visual Analysis Framework |
| [patchpanel](./patchpanel/) | Platform networking daemons |
| [pciguard](./pciguard/) | Daemon to secure external PCI devices (thunderbolt etc) |
| [perfetto_simple_producer](./perfetto_simple_producer/) | A simple producer of perfetto: An example demonstrating how to produce Perfetto performance trace data |
| [permission_broker](./permission_broker/) ||
| [policy_proto](./policy_proto/) | Build file to compile policy proto file |
| [policy_utils](./policy_utils/) | Tools and related library to set or override device policies |
| [power_manager](./power_manager/) | Userspace power management daemon and associated tools |
| [print_tools](./print_tools/) | Various tools related to the native printing system |
| [printscanmgr](./printscanmgr/) | ChromeOS Printing and Scanning Daemon |
| [private_computing](./private_computing/) | Daemon to save and retrieve device active date status into and from preserved file.
| [pwgtocanonij](./pwgtocanonij/) | CUPS filter for certain Canon printers |
| [regions](./regions/) ||
| [resourced](./resourced/) | Resource Management Daemon |
| [rgbkbd](./rgbkbd/) | ChromeOS RGB Keyboard Daemon |
| [rmad](./rmad/) | ChromeOS RMA Daemon |
| [run_oci](./run_oci/) | Minimalistic container runtime |
| [runtime_probe](./runtime_probe/) | Runtime probe tool for ChromeOS |
| [screen-capture-utils](./screen-capture-utils/) | Utilities for screen capturing (screenshot) |
| [secagentd](./secagentd/) | Daemon for detecting and reporting security related events |
| [secanomalyd](./secanomalyd/) | Daemon for detecting and reporting security anomalies |
| [secure-wipe](./secure-wipe/) | Secure disk wipe |
| [secure_erase_file](./secure_erase_file/) | Helper tools for securely erasing files from storage (e.g. keys and PII data) |
| [sepolicy](./sepolicy/) | SELinux policy for ChromeOS |
| [shadercached](./shadercached/) | Shader cache management daemon |
| [shill](./shill/) | ChromeOS Connection Manager |
| [sirenia](./sirenia/) | Minimalistic init written in Rust |
| [smbfs](./smbfs/) | FUSE-based filesystem for accessing Samba / Windows networking shares |
| [smbprovider](./smbprovider/) | Daemon for connecting Samba / Windows networking shares to the Files.app |
| [spaced](./spaced/) | Disk space information daemon |
| [st_flash](./st_flash/) ||
| [storage_info](./storage_info/) | Helper shell functions for retrieving disk information) |
| [swap_management](./swap_management/) | Swap management service |
| [syslog-cat](./syslog-cat/) | Helper command to forward stdout/stderr from process to syslog |
| [system-proxy](./system-proxy/) | Daemon for web proxy authentication support on ChromeOS |
| [system_api](./system_api/) | Headers and .proto files etc. to be shared with chromium |
| [timberslide](./timberslide/) | Tool for working with EC crashes for reporting purposes |
| [touch_firmware_calibration](./touch_firmware_calibration/) ||
| [tpm2-simulator](./tpm2-simulator/) | A software TPM 2.0 implementation (for testing/debugging) |
| [tpm_manager](./tpm_manager/) | Daemon and client for managing TPM setup and operations |
| [tpm_softclear_utils](./tpm_softclear_utils/) | Utilities that soft-clear TPM (for testing only) |
| [trim](./trim/) | Service to manage filesystem trim operations in the background |
| [trunks](./trunks/) | Middleware and resource manager for interfacing with TPM 2.0 hardware |
| [typecd](./typecd/) | System daemon to keep track of USB Type C state |
| [u2fd](./u2fd/) | U2FHID emulation daemon for systems with secure elements (not TPMs) |
| [ureadahead-diff](./ureadahead-diff/) | Tool to calculate difference between 2 ureadahead packs |
| [usb_bouncer](./usb_bouncer/) | Tools for managing USBGuard white-lists and configuration on ChromeOS |
| [userfeedback](./userfeedback/) | Various utilities to gather extended data for user feedback reports |
| [uwbd](./uwbd/) | Daemon for the UWB on ChromeOS |
| [verity](./verity/) | Userspace tools for working dm-verity (verified disk images) |
| [virtual_file_provider](./virtual_file_provider/) ||
| [vm_tools](./vm_tools/) | Utilities for Virtual Machine (VM) orchestration |
| [vtpm](./vtpm/) | ChromeOS virtual TPM Daemon |
| [wifi-testbed](./wifi-testbed/) | Tools for creating a WiFi testbed image |

# AOSP Project Directory

These projects can be found here:
https://chromium.googlesource.com/aosp/platform/
