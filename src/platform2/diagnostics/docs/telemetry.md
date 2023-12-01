# Telemetry

On-device telemetry API serves the clients on both Chromium and
platform. The [data sources listed table](#Telemetry-categories) could be
scattered around different services and it is our vision to hide those tedious
details away from our clients. In addition, single source will help the data
utilization easier to process on the server side if it is our client's final
destination.

We also support a [proactive event subscription](#Events) API make clients could
subscript the particular event and got real-time notified when the event
occurs.

If you can't find the things you want, [contact us][team-contact] for a quick
check on the latest status just in case the documentation is behind the
reality.

[team-contact]: mailto:cros-tdm-tpe-eng@google.com

[TOC]

## Usages

### Mojo interface

- `CrosHealthdProbeService` interface
    - `ProbeTelemetryInfo(categories)` can grab the data from selected
      `categories` from a single IPC call.
    - `ProbeProcessInfo(process_id)` can retrieve the
      [process information](#ProcessInfo) for a specific `process_id`.
    - `ProbeMultipleProcessInfo(process_ids, ignore_single_process_error)` can
      retrieve the [process information](#ProcessInfo) for the array of
      `process_ids` and errors if any occurred. Leave `process_ids` null can
      retrieve all current existing processes on the device; setting
      `ignore_single_process_error` to true will ignore any errors if occurred.
- `CrosHealthdEventService` interface
    - `AddEventObserver(category, observer)` for category(`EventCategoryEnum`)
      events.

See the Mojo interface comment for the detail.

Note that, __Strongly recommend__ to split your request into multiple and fetch
a subset of interesting categories in each call, and setup disconnect handler
to be able to return partial data. As `ProbeTelemetryInfo()` might not be
returned under certain critical situation. (e.g. `cros_healthd` got killed or
crash, a common cases is the seccomp vialation).

### CLI tool

`cros-health-tool` is a convenience tools **for testing**, it is not for production used.
We recommended to [reach us][team-contact] before using this in your project.

For telemetry, we can initiate a request via `cros-health-tool telem
--category=<xx>` where `<xx>` is the category name. The list of category names
could be checked via `cros-health-tool telem --help`.

For process, we can initiate a request via `cros-health-tool telem
--process=<process_id>,<process_id>,<process_id>` to retrieve single or multiple
process information or `cros-health-tool telem --process=all` to retrieve all
current existing processes. Adding `--ignore` can ignore single process errors.

For event, `cros-health-tool event --category=<xx>` where `<xx>` is the event
category name. The list of category names could be checked via `cros-health-tool
event --help`.

## Telemetry categories

###  Audio

#####  AudioInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| output_mute | bool | Is active output device mute or not. |
| input_mute | bool | Is active input device mute or not. |
| output_volume | uint64 | Active output device's volume in [0, 100]. |
| output_device_name | string | Active output device's name. |
| input_gain | uint32 | Active input device's gain in [0, 100]. |
| input_device_name | string | Active input device's name. |
| underruns | uint32 | Numbers of underruns. |
| severe_underruns | uint32 | Numbers of severe underruns. |

### AudioHardwareInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| audio_cards | [array&lt;AudioCard&gt;](#AudioCard) | Audio cards information. |

##### AudioCard
| Field | Type | Description |
| ----- | ---- | ----------- |
| alsa_id | string | The id used by ALSA(Advanced Linux Sound Architecture). |
| bus_device | [BusDevice?](#BusDevice) | The bus device. If omits, the card is belongs to a bus type which is not yet supported by Healthd. |
| hd_audio_codecs | [array&lt;HDAudioCodec&gt;](#HDAudioCodec) | The hd-audio codecs. |

##### HDAudioCodec
| Field | Type | Description |
| ----- | ---- | ----------- |
| name | string | The name. E.g. "ATI R6xx HDMI". |
| address | uint8 | The address. E.g. "0". |

###  Backlight

#####  BacklightInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| path | string | Path to this backlight on the system. Useful if the caller needs to<br />correlate with other information. |
| max_brightness | uint32 | Maximum brightness for the backlight. |
| brightness | uint32 | Current brightness of the backlight, between 0 and max_brightness. |

###  Battery

#####  BatteryInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| cycle_count | int64 | Current charge cycle count |
| voltage_now | double | Current battery voltage (V) |
| vendor | string | Manufacturer of the battery |
| serial_number | string | Serial number of the battery |
| charge_full_design | double | Designed capacity (Ah) |
| charge_full | double | Current Full capacity (Ah) |
| voltage_min_design | double | Desired minimum output voltage (V) |
| model_name | string | Model name of battery |
| charge_now | double | Current battery charge (Ah) |
| current_now | double | Current battery current (A) |
| technology | string | Technology of the battery. Battery chemistry. <br />e.g. "NiMH", "Li-ion", "Li-poly", "LiFe", "NiCd", "LiMn" |
| status | string | Status of the battery |
| manufacture_date | string? | Manufacture date converted to yyyy-mm-dd format. (Only available on Smart Battery) |
| temperature | uint64? | Temperature in 0.1K. Included when the main battery is a Smart Battery. (Only available on Smart Battery) |

####  Charge

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) AC Adapter Wattage |

####  EC

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) ePPID (Dell exclusive data) |
|  |  | (planned) Battery soft/hard error |
|  |  | (planned) MA code |


###  Bluetooth

####  Client

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) TX Bytes (total so far) |
|  |  | (planned) RX Bytets (total so far) |

####  Host

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) TX Bytes (total so far) |
|  |  | (planned) RX Bytets (total so far) |

#####  BluetoothAdapterInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| name | string | The name of the adapter. |
| address | string | The MAC address of the adapter. |
| powered | bool | Indicates whether the adapter is on or off. |
| num_connected_devices | uint32 | The number of devices connected to this adapter. |
| connected_devices | [array&lt;BluetoothDeviceInfo&gt;?](#BluetoothDeviceInfo) | The info of connected devices to this adapter. |
| discoverable | bool | The adapter is visible or not. |
| discovering | bool | The device discovery procedure is active or not. |
| uuids | array&lt;string&gt;? | The list of the available local services. |
| modalias | string? | Local Device ID information. |
| service_allow_list | array&lt;string&gt;? | List of allowed system devices. |
| supported_capabilities | [SupportedCapabilities?](#SupportedCapabilities) | A dictionary of supported capabilities. |

##### BluetoothDeviceInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| address | string | The MAC address of the device. |
| name | string? | The name of the device. |
| type | [BluetoothDeviceType](#BluetoothDeviceType) | The carriers supported by this remote device ("BR/EDR", "LE", or "DUAL"). |
| appearance | uint16? | The external appearance of the device. |
| modalias | string? | Remote Device ID information. |
| rssi | uint16? | Received Signal Strength Indicator. |
| mtu | uint16? | The Maximum Transmission Unit used in ATT communication. |
| uuids | array&lt;string&gt;? | The list of the available remote services. |
| battery_percentage | uint8? | The battery percentage of the device. |
| bluetooth_class | uint32? | The Bluetooth class of device (CoD) of the device. |

##### BluetoothDeviceType
| Enum | Description |
| ---- | ----------- |
| kUnmappedEnumField | An enum value not defined in this version of the enum definition. |
| kUnfound | Unfound type. |
| kBrEdr | BR/EDR. |
| kLe | LE. |
| kDual | DUAL. |

##### SupportedCapabilities
| Field | Type | Description |
| ----- | ---- | ----------- |
| max_adv_len | uint8 | Max advertising data length. |
| max_scn_rsp_len | uint8 | Max advertising scan response length. |
| min_tx_power | int16 | Min advertising tx power (dBm). |
| max_tx_power | int16 | Max advertising tx power (dBm). |

###  Bus

#####  BusDevice
| Field | Type | Description |
| ----- | ---- | ----------- |
| vendor_name | string | The vendor / product name of the device. These are extracted from the<br />databases on the system and should only be used for showing / logging.<br />Don't use these to identify the devices. |
| product_name | string | The class of the device. |
| device_class | [BusDeviceClass](#BusDeviceClass) | The info related to specific bus type. |
| bus_info | [BusInfo](#BusInfo) | These fields can be used to classify / identify the pci devices. See the<br />pci.ids database for the values. (https://github.com/gentoo/hwids) |

##### BusDeviceClass
| Enum | Description |
| ---- | ----------- |
| kOthers | Others. |
| kDisplayController | Display controller. |
| kEthernetController | Ethernet Controller. |
| kWirelessController | Wireless Controller. |
| kBluetoothAdapter | Bluetooth Adapter. |
| kThunderboltController | Thunderbolt Controller. |
| kAudioCard | Audio Card. |


#####  BusInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| pci_bus_info | [PciBusInfo](#PciBusInfo) | (union/one-of type) This field is valid only if the info is related to pci. |
| usb_bus_info | [UsbBusInfo](#UsbBusInfo) | (union/one-of type) This field is valid only if the info is related to usb. |
| thunderbolt_bus_info | [ThunderboltBusInfo](#ThunderboltBusInfo) | (union/one-of type) This field is valid only if the info is related to thunderbolt. |

####  PCIe

#####  PciBusInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| class_id | uint8 |  |
| subclass_id | uint8 |  |
| prog_if_id | uint8 |  |
| vendor_id | uint16 |  |
| device_id | uint16 |  |
| driver | string? | The driver used by the device. This is the name of the matched driver which<br />is registered in the kernel. See "{kernel root}/drivers/". for the list of<br />the built in drivers. |

####  Thunderbolt

#####  ThunderboltBusInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| security_level | [ThunderboltSecurityLevel](#ThunderboltSecurityLevel) | Security level none, user, secure, dponly. |
| thunderbolt_interfaces | [array&lt;ThunderboltBusInterfaceInfo&gt;](#ThunderboltBusInterfaceInfo) | Info of devices attached to the controller. |

##### ThunderboltSecurityLevel
| Enum | Description |
| ---- | ----------- |
| kNone | None. |
| kUserLevel | User level. |
| kSecureLevel | Secure level. |
| kDpOnlyLevel | DP only level. |
| kUsbOnlyLevel | USB only level. |
| kNoPcieLevel | No PCIe level. |

#####  ThunderboltBusInterfaceInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| vendor_name | string | Vendor name of connected device interface. |
| device_name | string | Product name of connected device interface. |
| device_type | string | Type of device. |
| device_uuid | string | The device unique id. |
| tx_speed_gbs | uint32 | Transmit link speed for thunderbolt interface. |
| rx_speed_gbs | uint32 | Receive link speed for thunderbolt interface. |
| authorized | bool | Connection is authorized or not. |
| device_fw_version | string | nvm firmware version. |

####  USB

#####  UsbBusInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| class_id | uint8 | These fields can be used to classify / identify the usb devices. See the<br />usb.ids database for the values. (https://github.com/gentoo/hwids) |
| subclass_id | uint8 |  |
| protocol_id | uint8 |  |
| vendor_id | uint16 |  |
| product_id | uint16 |  |
| interfaces | [array&lt;UsbBusInterfaceInfo&gt;](#UsbBusInterfaceInfo) | The usb interfaces under the device. A usb device has at least one<br />interface. Each interface may or may not work independently, based on each<br />device. This allows a usb device to provide multiple features.<br />The interfaces are sorted by the |interface_number| field. |
| fwupd_firmware_version_info | [FwupdFirmwareVersionInfo?](#FwupdFirmwareVersionInfo) | The firmware version obtained from fwupd. |

##### FwupdFirmwareVersionInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| version | string | The string form of the firmware version. |
| version_format | [FwupdVersionFormat](#FwupdVersionFormat) | The format for parsing the version string. |

##### FwupdVersionFormat
| Enum | Description |
| ---- | ----------- |
| kUnmappedEnumField | An enum value not defined in this version of the enum definition. |
| kUnknown | Unknown version format. |
| kPlain | An unidentified format text string. |
| kNumber | A single integer version number. |
| kPair | Two AABB.CCDD version numbers. |
| kTriplet | Microsoft-style AA.BB.CCDD version numbers. |
| kQuad | UEFI-style AA.BB.CC.DD version numbers. |
| kBcd | Binary coded decimal notation. |
| kIntelMe | Intel ME-style bitshifted notation. |
| kIntelMe2 | Intel ME-style A.B.CC.DDDD notation. |
| kSurfaceLegacy | Legacy Microsoft Surface 10b.12b.10b. |
| kSurface | Microsoft Surface 8b.16b.8b. |
| kDellBios | Dell BIOS BB.CC.DD style. |
| kHex | Hexadecimal 0xAABCCDD style. |

#####  UsbBusInterfaceInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| interface_number | uint8 | The zero-based number (index) of the interface. |
| class_id | uint8 | These fields can be used to classify / identify the usb interfaces. See the<br />usb.ids database for the values. |
| subclass_id | uint8 |  |
| protocol_id | uint8 |  |
| driver | string? | The driver used by the device. This is the name of the matched driver which<br />is registered in the kernel. See "{kernel root}/drivers/". for the list of<br />the built in drivers. |

###  CPU

#####  CpuInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| num_total_threads | uint32 | Number of total threads available. |
| architecture | [CpuArchitectureEnum](#CpuArchitectureEnum) | The CPU architecture - it's assumed all of a device's CPUs share an<br />architecture. |
| physical_cpus | [array&lt;PhysicalCpuInfo&gt;](#PhysicalCpuInfo) | Information about the device's physical CPUs. |
| temperature_channels | [array&lt;CpuTemperatureChannel&gt;](#CpuTemperatureChannel) | Information about the CPU temperature channels. |
| keylocker_info | [KeylockerInfo?](#KeylockerInfo) | Information about keylocker. |
| virtualization | [VirtualizationInfo?](#VirtualizationInfo) | The general virtualization info. Guaranteed to be not null unless the version doesn't match. |
| vulnerabilities | [map&lt;string, VulnerabilityInfo&gt;?](#VulnerabilityInfo) | The cpu vulnerability info. The key is the name of the vulnerability. Guaranteed to be not null unless the version doesn't match. |

##### CpuArchitectureEnum
| Enum | Description |
| ---- | ----------- |
| kUnknown | Unknown. |
| kX86_64 | x86_64. |
| kAArch64 | Arch64. |
| kArmv7l | Armv7l. |

#### Virtualization

| Field | Type | Description |
| ----- | ---- | ----------- |
| VMXLockedInBIOS |  | (planned) Is VMX locked by the device BIOS |
| VMXEnabled |  | (planned) VMX - Intel Virtualisation is used to control certain features such as crostini. It is useful to know if it is enabled to allow us to gate or preempt issues with features like crostini. |
| DevKVMExists |  | (planned) This allows us to verify if a processor supports virtualisation or not. |

##### VirtualizationInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| has_kvm_device | bool | Whether the /dev/kvm device exists. |
| is_smt_active | bool | Whether SMT is active. This will always be false if SMT detection is not supported by the kernel of this device. |
| smt_control | [SMTControl](#SMTControl) | The state of SMT control. |

##### SMTControl
| Enum | Description |
| ---- | ----------- |
| kUnmappedEnumField | This is required for backwards compatibility, should not be used. |
| kOn | SMT is enabled. |
| kOff | SMT is disabled. |
| kForceOff | SMT is force disabled. Cannot be changed. |
| kNotSupported | SMT is not supported by the CPU. |
| kNotImplemented | SMT runtime toggling is not implemented for the architecture, or the kernel version doesn't support SMT detection yet. |

#### Vulnerability

##### VulnerabilityInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| status | [Status](#Status) | The status of the vulnerability. |
| message | string | The description of the vulnerability. |

##### Status
| Enum | Description |
| ---- | ----------- |
| kUnmappedEnumField | This is required for backwards compatibility, should not be used. |
| kNotAffected | Not affected by this vulnerability. |
| kVulnerable | Vulnerable by this vulnerability. |
| kMitigation | Vulnerability is mitigated. |
| kUnknown | Vulnerability is unknown. |
| kUnrecognized | Vulnerability is unrecognized by parser. |

####  KeyLocker

#####  KeylockerInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| keylocker_configured | bool | Has Keylocker been configured or not. |

####  Physical Core

#####  PhysicalCpuInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| model_name | string? | The CPU model name, if available.<br />For Arm devices, we will return SoC model instead. |
| logical_cpus | [array&lt;LogicalCpuInfo&gt;](#LogicalCpuInfo) | Logical CPUs corresponding to this physical CPU. |
| flags | array&lt;string&gt;? | The cpu flags, labelled as |flags| in x86 architecture and |Features| in ARM architecture. |
| virtualization | [CpuVirtualizationInfo?](#CpuVirtualizationInfo) | The virtualization info of this cpu. |

##### CpuVirtualizationInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| type | [Type](#Type) | The type of cpu hardware virtualization. |
| is_enabled | bool | Whether virtualization is enabled. |
| is_locked | bool | Whether the virtualization configuration is locked and cannot be modified. This is usually set by the BIOS to prevent the OS changing the setting after booting into the OS. |

##### Type
| Enum | Description |
| ---- | ----------- |
| kUnmappedEnumField | This is required for backwards compatibility, should not be used. |
| kVMX | The cpu supports Intel virtualization (VT-x). |
| kSVM | The cpu supports AMD virtualization (AMD-V). |

#####  LogicalCpuInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| max_clock_speed_khz | uint32 | The max CPU clock speed in kHz. |
| scaling_max_frequency_khz | uint32 | Maximum frequency the CPU is allowed to run at, by policy. |
| scaling_current_frequency_khz | uint32 | Current frequency the CPU is running at. |
| user_time_user_hz | uint64 | Time spent in user mode since last boot. USER_HZ can be converted to<br />seconds with the conversion factor given by sysconf(_SC_CLK_TCK). |
| system_time_user_hz | uint64 | Time spent in system mode since last boot. USER_HZ can be converted to<br />seconds with the conversion factor given by sysconf(_SC_CLK_TCK). |
| idle_time_user_hz | uint64 | Idle time since last boot. USER_HZ can be converted to seconds with the<br />conversion factor given by sysconf(_SC_CLK_TCK). |
| c_states | [array&lt;CpuCStateInfo&gt;](#CpuCStateInfo) | Information about the logical CPU's time in various C-states. |
|  |  | (planned) total_time_in_ticks (time in state since beginning) |
|  |  | (planned) Current Throttle% (for each logical) |
|  |  | (planned) Used percentage |
|  |  | (planned) Average Utilization percentage |

####  C State

#####  CpuCStateInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| name | string | Name of the state. |
| time_in_state_since_last_boot_us | uint64 | Time spent in the state since the last reboot, in microseconds. |

####  Temperature

#####  CpuTemperatureChannel
| Field | Type | Description |
| ----- | ---- | ----------- |
| label | string? | Temperature channel label, if found on the device. |
| temperature_celsius | int32 | CPU temperature in Celsius. |

###  Dell EC

####  BIOS Internal Log

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Power event log - event code / timestamp |
|  |  | (planned) LED code log - event code / timestamp |

####  Cable

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Cable Name |
|  |  | (planned) Cable Status (installed and not installed) |
|  |  | (planned) Cable change history |
|  |  | (planned) Cable time stamp |

####  Thermistor

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Location |
|  |  | (planned) Temp |
|  |  | (planned) Timestamp |
|  |  | (planned) Thermal zone |
|  |  | (planned) Thermal trip |
|  |  | (planned) Thermal hystereis |


###  Display

#####  DisplayInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| edp_info | [EmbeddedDisplayInfo](#EmbeddedDisplayInfo) | Embedded display info. |
| dp_infos | [array&lt;ExternalDisplayInfo&gt;?](#ExternalDisplayInfo) | External display info. |

####  Embedded Display

#####  EmbeddedDisplayInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| privacy_screen_supported | bool | Privacy screen is supported or not. |
| privacy_screen_enabled | bool | Privacy screen is enabled or not. |
| display_width | uint32? | Display width in millimeters. |
| display_height | uint32? | Display height in millimeters. |
| resolution_horizontal | uint32? | Horizontal resolution. |
| resolution_vertical | uint32? | Vertical resolution. |
| refresh_rate | double? | Refresh rate. |
| manufacturer | string? | Three letter manufacturer ID. |
| model_id | uint16? | Manufacturer product code. |
| serial_number | uint32? | 32 bits serial number. |
| manufacture_week | uint8? | Week of manufacture. |
| manufacture_year | uint16? | Year of manufacture. |
| edid_version | string? | EDID version. |
| input_type | [DisplayInputType](#DisplayInputType) | Digital or analog input. |
| display_name | string? | Name of display product. |

##### DisplayInputType
| Enum | Description |
| ---- | ----------- |
| kUnmappedEnumField | An enum value not defined in this version of the enum definition. |
| kDigital | Digital input. |
| kAnalog | Analog input. |

####  ExternalDisplay
| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Vendor Specific Data |

#####  ExternalDisplayInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| display_width | uint32? | Display width in millimeters. |
| display_height | uint32? | Display height in millimeters. |
| resolution_horizontal | uint32? | Horizontal resolution. |
| resolution_vertical | uint32? | Vertical resolution. |
| refresh_rate | double? | Refresh rate. |
| manufacturer | string? | Three letter manufacturer ID. |
| model_id | uint16? | Manufacturer product code. |
| serial_number | uint32? | 32 bits serial number. |
| manufacture_week | uint8? | Week of manufacture. |
| manufacture_year | uint16? | Year of manufacture. |
| edid_version | string? | EDID version. |
| input_type | [DisplayInputType](#DisplayInputType) | Digital or analog input. |
| display_name | string? | Name of display product. |

###  Fan

#####  FanInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| speed_rpm | uint32 | Fan speed in RPM. |

####  Dell

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Fan speed in RPM. Data source: Dell EC |
|  |  | (planned) Fan location. Data source: Dell EC |


###  Firmware

####  EFI

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) EFIFirmwareBitness. Identify if UEFI is IA32 or x86_64 as we support some 32bit UEFI devices |


###  Graphic

#####  GraphicsInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| gles_info | [GLESInfo](#GLESInfo) | OpenGL | ES information. |
| egl_info | [EGLInfo](#EGLInfo) | EGL information. |

####  EGL

#####  EGLInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| version | string | EGL version. |
| vendor | string | EGL vendor. |
| client_api | string | EGL client API. |
| extensions | array&lt;string&gt; | EGL extensions. |

####  GL ES

#####  GLESInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| version | string | GL version. |
| shading_version | string | GL shading version. |
| vendor | string | GL vendor. |
| renderer | string | GL renderer. |
| extensions | array&lt;string&gt; | GL extensions. |


###  Input

##### InputInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| touchpad_library_name | string | The touchpad library name used by the input stack. |
| touchscreen_devices | [array&lt;TouchscreenDevice&gt;](#TouchscreenDevice) | The touchscreen devices. |

##### TouchscreenDevice
| Field | Type | Description |
| ----- | ---- | ----------- |
| input_device | [InputDevice](#InputDevice) | The input device of this touchscreen. |
| touch_points | int32 | Number of touch points this device supports (0 if unknown). |
| has_stylus | bool | True if the specified touchscreen device is stylus capable. |
| has_stylus_garage_switch | bool | True if there is a garage/dock switch associated with the stylus. |

##### InputDevice
| Field | Type | Description |
| ----- | ---- | ----------- |
| name | string | Name of the device. |
| connection_type | [ConnectionType](#ConnectionType) | The connection type of the input device. |
| physical_location | string | The physical location(port) associated with the input device. This is (supposed to be) stable between reboots and hotplugs. However this may not always be set and will change when the device is connected via a different port. |
| is_enabled | bool | If the device is enabled, and whether events should be dispatched to UI. |

##### ConnectionType
| Enum | Description |
| ---- | ----------- |
| kUnmappedEnumField | For mojo backward compatibility. |
| kInternal | Internally connected input device. |
| kUSB | Known externally connected usb input device. |
| kBluetooth | Known externally connected bluetooth input device. |
| kUnknown | Device that may or may not be an external device. |

###  Lid

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) lid status. Open or Close. |


###  Log

####  OS crash

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) system_crach_log (detail in confluence) |


###  Memory

####  General

#####  MemoryInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| total_memory_kib | uint32 | Total memory, in KiB. |
| free_memory_kib | uint32 | Free memory, in KiB. |
| available_memory_kib | uint32 | Available memory, in KiB. |
| page_faults_since_last_boot | uint64 | Number of page faults since the last boot. |
| memory_encryption_info | [MemoryEncryptionInfo?](#MemoryEncryptionInfo) | Memory Encryption info. |

####  Memory Encryption

#####  MemoryEncryptionInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| encryption_state | [EncryptionState](#EncryptionState) | Memory encryption state. |
| max_key_number | uint32 | Encryption key length. |
| key_length | uint32 | Encryption key length. |
| active_algorithm | [CryptoAlgorithm](#CryptoAlgorithm) | Crypto algorithm currently used. |

##### EncryptionState
| Enum | Description |
| ---- | ----------- |
| kUnknown | Unknown. |
| kEncryptionDisabled | Encryption is disabled. |
| kTmeEnabled | Tme is enabled. |
| kMktmeEnabled | Multi-key Tme is enabled. |

##### CryptoAlgorithm
| Enum | Description |
| ---- | ----------- |
| kUnknown | Unknown. |
| kAesXts128 | AesXts128. |
| kAesXts256 | AesXts256. |

###  Misc

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Dell ePSA report |
|  |  | (planned) Customer name/defined |


###  Network

####  Health

#####  Network {#network-health-struct}
| Field | Type | Description |
| ----- | ---- | ----------- |
| type | [NetworkType](#NetworkType) | The network interface type. |
| state | [NetworkState](#NetworkState) | The current status of this network. e.g. Online, Disconnected. |
| guid | string? | The unique identifier for the network when a network service exists. |
| name | string? | The user facing name of the network if available. |
| mac_address | string? | Optional string for the network's mac_address. |
| signal_strength | uint32? | Signal strength of the network provided only for wireless networks. Values<br />are normalized between 0 to 100 inclusive. Values less than 30 are<br />considered potentially problematic for the connection. See<br />src/platform2/shill/doc/service-api.txt for more details. |
| ipv4_address | string? | Optional string for the network's ipv4_address. This is only intended to be<br />used for display and is not meant to be parsed. |
| ipv6_addresses | array&lt;string&gt; | Optional list of strings for the network's ipv6_addresses. A single network<br />can have multiple addresses (local, global, temporary etc.). This is only<br />intended to be used for display and is not meant to be parsed. |
| portal_state | [PortalState](#PortalState) | An enum of the network's captive portal state. This information is<br />supplementary to the NetworkState. |
| signal_strength_stats | [SignalStrengthStats?](#SignalStrengthStats) | The statistics of the signal strength for wireless networks over a 15<br />minute period. See SignalStrengthStats for more details. |

##### NetworkType
| Enum | Description |
| ---- | ----------- |
| kAll | All. |
| kCellular | Cellular. |
| kEthernet | Ethernet. |
| kMobile | Mobile includes Cellular, and Tether. |
| kTether | Tether. |
| kVPN | VPN. |
| kWireless | Wireles includes Cellular, Tether, and WiFi. |
| kWiFi | WiFi. |

##### NetworkState
| Enum | Description |
| ---- | ----------- |
| kUninitialized | The network type is available but not yet initialized. |
| kDisabled | The network type is available but disabled or disabling. |
| kProhibited | The network type is prohibited by policy. |
| kNotConnected | The network type is available and enabled or enabling, but no network connection has been established. |
| kConnecting | The network type is available and enabled, and a network connection is in progress. |
| kPortal | The network is in a portal state. |
| kConnected | The network is in a connected state, but connectivity is limited. |
| kOnline | The network is connected and online. |

##### PortalState
| Enum | Description |
| ---- | ----------- |
| kUnknown | The network is not connected or the portal state is not available. |
| kOnline | The network is connected and no portal is detected. |
| kPortalSuspected | A portal is suspected but no redirect was provided. |
| kPortal | The network is in a portal state with a redirect URL. |
| kProxyAuthRequired | A proxy requiring authentication is detected. |
| kNoInternet | The network is connected but no internet is available and no proxy was detected. |

##### SignalStrengthStats
| Field | Type | Description |
| ----- | ---- | ----------- |
| average | float | A value representing the average recent signal strength. |
| deviation | float | A value representing the recent deviation of the signal strength. |
| samples | array&lt;uint8&gt; | The samples of the signal strength over the polled period. This value is only for debugging and diagnostics purposes. The other indicators in this struct are the canonical stats for the signal strength. Max Size: (12 * 15) = 180 samples. |

#####  NetworkHealthState
| Field | Type | Description |
| ----- | ---- | ----------- |
| networks | [array&lt;Network&gt;](#network-health-struct) | This is a list of networking devices and any associated connections.<br />Only networking technologies that are present on the device are included.<br />Networks will be sorted with active connections listed first. |

####  Interface

#####  NetworkInterfaceInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| wireless_interface_info | [WirelessInterfaceInfo](#WirelessInterfaceInfo) | Wireless interfaces. |

####  LAN

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) RX Bytes |
|  |  | (planned) TX Bytes |
|  |  | (planned) Interface Name |
|  |  | (planned) LAN Speed |

####  WLAN

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) RX Bytes |
|  |  | (planned) TX Bytes |
|  |  | (planned) Radio On/Off |

####  WWAN / modem

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Manufacturer |
|  |  | (planned) Model |
|  |  | (planned) IMEI |

####  Wifi Interface

#####  WirelessInterfaceInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| interface_name | string | Interface name. |
| power_management_on | bool | Is power management enabled for wifi or not. |
| wireless_link_info | [WirelessLinkInfo?](#WirelessLinkInfo?) | Link info only available when device is connected to an access point. |
| access_point_address_str | string | Access point address. |
| tx_bit_rate_mbps | uint32 | Tx bit rate measured in Mbps. |
| rx_bit_rate_mbps | uint32 | Rx bit rate measured in Mbps. |
| tx_power_dBm | int32 | Transmission power measured in dBm. |
| encyption_on | bool | Is wifi encryption key on or not. |
| link_quality | uint32 | Wifi link quality. |
| signal_level_dBm | int32 | Wifi signal level in dBm. |

##### WirelessLinkInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| access_point_address_str | string | Access point address. |
| tx_bit_rate_mbps | uint32 | Tx bit rate measured in Mbps. |
| rx_bit_rate_mbps | uint32 | Rx bit rate measured in Mbps. |
| tx_power_dBm | int32 | Transmission power measured in dBm. |
| encyption_on | bool | Is wifi encryption key on or not. |
| link_quality | uint32 | Wifi link quality. |
| signal_level_dBm | int32 | Wifi signal level in dBm. |

###  OS

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) OS uptime |
|  |  | (planned) PQL (Process Queue Length) |
|  |  | (planned) hostname |


###  Performance

####  Booting

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Last restart time (differ from shutdown?) |

#####  BootPerformanceInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| boot_up_seconds | double | Total time since power on to login screen prompt. |
| boot_up_timestamp | double | The timestamp when power on. |
| shutdown_seconds | double | Total time(rough) since shutdown start to power off.<br />Only meaningful when shutdown_reason is not "N/A". |
| shutdown_timestamp | double | The timestamp when shutdown.<br />Only meaningful when shutdown_reason is not "N/A". |
| shutdown_reason | string | The shutdown reason (including reboot). |
| tpm_initialization_seconds | double? | TPM initialization time. |


###  Sensor

#####  SensorInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| lid_angle | uint16? | Angle between lid and base. |
| sensors | array&lt;[Sensor](#Sensor)&gt;? | Information about the device's sensors. |

##### Sensor
| Field | Type | Description |
| ----- | ---- | ----------- |
| name | string? | The name of sensor. |
| device_id | int32 | The ID of sensor. |
| type | [Type](#Type) | The type of sensor. |
| location | [Location](#Location) | The location of sensor. |

##### Type
| Enum | Description |
| ---- | ----------- |
| kUnmappedEnumField | For mojo backward compatibility, should not be used. |
| kAccel | Accelerometer. |
| kLight | Light sensor. |
| kGyro | Angular velocity sensor, also known as Gyro sensor. |
| kAngle | Angle sensor. |
| kGravity | Gravity sensor. |
| kMagn | Magnetometer. |

##### Location
| Enum | Description |
| ---- | ----------- |
| kUnmappedEnumField | For mojo backward compatibility, should not be used. |
| kUnknown | Unknown location. |
| kBase | Base. |
| kLid | Lid. |
| kCamera | Camera. |


###  Storage

####  Device

#####  NonRemovableBlockDeviceInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| bytes_read_since_last_boot | uint64 | Bytes read since last boot. |
| bytes_written_since_last_boot | uint64 | Bytes written since last boot. |
| read_time_seconds_since_last_boot | uint64 | Time spent reading since last boot. |
| write_time_seconds_since_last_boot | uint64 | Time spent writing since last boot. |
| io_time_seconds_since_last_boot | uint64 | Time spent doing I/O since last boot. Counts the time the disk and queue<br />were busy, so unlike the fields above, parallel requests are not counted<br />multiple times. |
| discard_time_seconds_since_last_boot | uint64? | Time spent discarding since last boot. Discarding is writing to clear<br />blocks which are no longer in use. Supported on kernels 4.18+. |
| device_info | [BlockDeviceInfo](#BlockDeviceInfo)? | Device specific info. |
| vendor_id | [BlockDeviceVendor](#BlockDeviceVendor) | Device vendor identification. |
| product_id | [BlockDeviceProduct](#BlockDeviceProduct) | Device product identification. |
| revision | [BlockDeviceRevision](#BlockDeviceRevision) | Device revision. |
| name | string | Device model. |
| size | uint64 | Device size in bytes. |
| firmware_version | [BlockDeviceFirmware](#BlockDeviceFirmware) | Firmware version. |
| type | string | Storage type, could be MMC / NVMe / ATA, based on udev subsystem. |
| purpose | [StorageDevicePurpose](#StorageDevicePurpose) | Purpose of the device e.g. "boot", "swap". |
| path | string | The path of this storage on the system. It is useful if caller needs to<br />correlate with other information. |
| manufacturer_id | uint8 | Manufacturer ID, 8 bits. |
| serial | uint32 | PSN: Product serial number, 32 bits |

##### BlockDeviceInfo
(Union/one-of type) The device-specific info.

| Field | Type | Description |
| ----- | ---- | ----------- |
| nvme_device_info | [NvmeDeviceInfo](#NvmeDeviceInfo) | (NVMe only) |
| emmc_device_info | [EmmcDeviceInfo](#EmmcDeviceInfo) | (eMMC only) |
| ufs_device_info | [UfsDeviceInfo](#UfsDeviceInfo) | (UFS only) |

##### NvmeDeviceInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| subsystem_vendor | uint32 | The manufacturer ID. |
| subsystem_device | uint32 | The product ID. |
| pcie_rev | uint8 | The product revision. |
| firmware_rev | uint64 | The firmware revision. |

##### EmmcDeviceInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| manfid | uint16 | The manufacturer ID. |
| pnm | uint64 | The product name. |
| prv | uint8 | The product revision. |
| fwrev | uint64 | The firmware revision. |

##### UfsDeviceInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| jedec_manfid | uint16 | The JEDEC manufacturer ID. |
| fwrev | uint64 | The firmware revision. |

##### BlockDeviceVendor
(Union/one-of type) The manufacturer of the block device.

| Field | Type | Description |
| ----- | ---- | ----------- |
| nvme_subsystem_vendor | uint32 | (NVMe only) The manufacturer ID. |
| emmc_oemid | uint16 | (eMMC only) The manufacturer ID. |
| other | uint16 | Unsupported. |
| unknown | uint64 | Unknown. |
| jedec_manfid | uint16 | (UFS only) The JEDEC manufacturer ID. |

##### BlockDeviceProduct
(Union/one-of type) The manufacturer-specific product identifier.

| Field | Type | Description |
| ----- | ---- | ----------- |
| nvme_subsystem_device | uint32 | (NVMe only) The product ID. |
| emmc_pnm | uint64 | (eMMC only) The product name. |
| other | uint16 | Unsupported. |
| unknown | uint64 | Unknown. |

##### BlockDeviceRevision
(Union/one-of type) The revision of the device's hardware.

| Field | Type | Description |
| ----- | ---- | ----------- |
| nvme_pcie_rev | uint8 | (NVMe only) The product revision. |
| emmc_prv | uint8 | (eMMC only) The product revision. |
| other | uint16 | Unsupported. |
| unknown | uint64 | Unknown. |

##### BlockDeviceFirmware
(Union/one-of type) The revision of the device's firmware.

| Field | Type | Description |
| ----- | ---- | ----------- |
| nvme_firmware_rev | uint64 | (NVMe only) The firmware revision. |
| emmc_fwrev | uint64 | (eMMC only) The firmware revision. |
| other | uint16 | Unsupported. |
| unknown | uint64 | Unknown. |
| ufs_fwrev | uint64 | (UFS only) The firmware revision. |

##### StorageDevicePurpose
| Enum | Description |
| ---- | ----------- |
| kUnknown | Unknown. |
| kBootDevice | Boot device. |
| kSwapDevice | Swap device. |

####  Device (SMART)

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) SMART - Temperature |
|  |  | (planned) SMART - total block read |
|  |  | (planned) SMART - total block write |
|  |  | (planned) SMART - model name |
|  |  | (planned) SMART - Temperature |
|  |  | (planned) SMART - power cycle count |
|  |  | (planned) SMART - power on hours |
|  |  | (planned) NVMe Dell Smart Attribute |

####  IO

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Idle time |

####  Logical Drive

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Name |
|  |  | (planned) Size_MB |
|  |  | (planned) Type |
|  |  | (planned) Freespace_MB |

####  Others

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) ePPID (Dell exclusive data) |

####  Partition

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) LSB size |
|  |  | (planned) Partition size |
|  |  | (planned) Partition Free Size |

####  StatefulPartition

#####  StatefulPartitionInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| available_space | uint64 | Available space for user data storage in the device in bytes. |
| total_space | uint64 | Total space for user data storage in the device in bytes. |
| filesystem | string | File system on stateful partition. e.g. ext4. |
| mount_source | string | Source of stateful partition. e.g. /dev/mmcblk0p1. |


###  System

####  CPU

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) CPU - serial number |

####  DMI (SMBIOS)

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) DIMM - location |
|  |  | (planned) DIMM - manufacturer |
|  |  | (planned) DIMM - part number |
|  |  | (planned) DIMM - serial number |
|  |  | (planned) BIOS Version |
|  |  | (planned) Chassis type/System Type |
|  |  | (planned) Motherboard product name |
|  |  | (planned) Motherboard serial number |
|  |  | (planned) Motherboard version |
|  |  | (planned) Service Tag |

#####  DmiInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| bios_vendor | string? | The BIOS vendor. |
| bios_version | string? | The BIOS version. |
| board_name | string? | The product name of the motherboard. |
| board_vendor | string? | The vendor of the motherboard. |
| board_version | string? | The version of the motherboard. |
| chassis_vendor | string? | The vendor of the chassis. |
| chassis_type | uint64? | The chassis type of the device. The values reported by chassis type are<br />mapped in<br />www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.0.0.pdf. |
| product_family | string? | The product family name. |
| product_name | string? | The product name (model) of the system. |
| product_version | string? | The product version. |
| sys_vendor | string? | The system vendor name. |

####  OS Env

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Language locale |
|  |  | (planned) Display language |
|  |  | (planned) timezone |

####  OS Image

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) OS Architecture (x86, x64, arm, arm64) |

#####  OsInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| code_name | string | Google code name for the given model. While it is OK to use this string for<br />human-display purposes (such as in a debug log or help dialog), or for a<br />searchable-key in metrics collection, it is not recommended to use this<br />property for creating model-specific behaviors. |
| marketing_name | string? | Contents of CrosConfig in /arc/build-properties/marketing-name. |
| os_version | [OsVersion](#OsVersion) | The OS version of the system. |
| boot_mode | [BootMode](#BootMode) | The boot flow used by the current boot. |
| oem_name | string? | Contents of CrosConfig in /branding/oem-name. |

##### BootMode
| Enum | Description |
| ---- | ----------- |
| kUnknown | Unknown. |
| kCrosSecure | Boot with ChromeOS firmware. |
| kCrosEfi | Boot with EFI. |
| kCrosLegacy | Boot with Legacy BIOS. |
| kCrosEfiSecure | Boot with EFI security boot. |

#####  OsVersion
| Field | Type | Description |
| ----- | ---- | ----------- |
| release_milestone | string | The OS version release milestone (e.g. "87"). |
| build_number | string | The OS version build number (e.g. "13544"). |
| patch_number | string | The OS version patch number (e.g. "59.0"). |
| release_channel | string | The OS release channel (e.g. "stable-channel"). |

####  Time zone

#####  TimezoneInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| posix | string | The timezone of the device in POSIX standard. |
| region | string | The timezone region of the device. |

####  VPD

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Dell product name |
|  |  | (planned) Asset Tag |
|  |  | (planned) UUID |
|  |  | (planned) System ID |

#####  VpdInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| serial_number | string? | A unique identifier of the device. (Required RO VPD field) |
| region | string? | Defines a market region where devices share a particular configuration of<br />keyboard layout, language, and timezone. (Required VPD field) |
| mfg_date | string? | The date the device was manufactured. (Required RO VPD field)<br />Format: YYYY-MM-DD. |
| activate_date | string? | The date the device was first activated. (Runtime RW VPD field)<br />Format: YYYY-WW. |
| sku_number | string? | The product SKU number. (Optional RO VPD field. b/35512367) |
| model_name | string? | The product model name. (Optional RO VPD field. b/35512367) |
| oem_name | string? | OEM name of the device. (Optional RO VPD field) |


###  TPM

#####  TpmInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| version | [TpmVersion](#TpmVersion) | TPM version related information. |
| status | [TpmStatus](#TpmStatus) | TPM status related information. |
| dictionary_attack | [TpmDictionaryAttack](#TpmDictionaryAttack) | TPM dictionary attack (DA) related information. |
| attestation | [TpmAttestation](#TpmAttestation) | TPM attestation related information. |
| supported_features | [TpmSupportedFeatures](#TpmSupportedFeatures) | TPM supported features information. |
| did_vid | string? | [Do NOT use] TPM did_vid file. This field is only used in Cloudready<br />project. It is going to drop the support in few milestone. |

####  Attestation

#####  TpmAttestation
| Field | Type | Description |
| ----- | ---- | ----------- |
| prepared_for_enrollment | bool | Is prepared for enrollment? True if prepared for *any* CA. |
| enrolled | bool | Is enrolled (AIK certificate created)? True if enrolled with *any* CA. |

####  Dictionary Attack

#####  TpmDictionaryAttack
| Field | Type | Description |
| ----- | ---- | ----------- |
| counter | uint32 | The current dictionary attack counter value. |
| threshold | uint32 | The current dictionary attack counter threshold. |
| lockout_in_effect | bool | Whether the TPM is in some form of dictionary attack lockout. |
| lockout_seconds_remaining | uint32 | The number of seconds remaining in the lockout. |

####  TPM Status

#####  TpmStatus
| Field | Type | Description |
| ----- | ---- | ----------- |
| enabled | bool | Whether a TPM is enabled on the system. |
| owned | bool | Whether the TPM has been owned. |
| owner_password_is_present | bool | Whether the owner password is still retained. |

#####  TpmSupportedFeatures
| Field | Type | Description |
| ----- | ---- | ----------- |
| support_u2f | bool | Whether the u2f is supported or not. |
| support_pinweaver | bool | Whether the pinweaver is supported or not. |
| support_runtime_selection | bool | Whether the platform supports runtime TPM selection or not. |
| is_allowed | bool | Whether the TPM is allowed to use or not. |

#####  TpmVersion
| Field | Type | Description |
| ----- | ---- | ----------- |
| gsc_version | [TpmGSCVersion](#TpmGSCVersion) | GSC version. |
| family | uint32 | TPM family. We use the TPM 2.0 style encoding, e.g.:<br /> * TPM 1.2: "1.2" -> 0x312e3200<br /> * TPM 2.0: "2.0" -> 0x322e3000 |
| spec_level | uint64 | TPM spec level. |
| manufacturer | uint32 | Manufacturer code. |
| tpm_model | uint32 | TPM model number. |
| firmware_version | uint64 | Firmware version. |
| vendor_specific | string? | Vendor specific information. |

##### TpmGSCVersion
| Enum | Description |
| ---- | ----------- |
| kNotGSC | For the devices which cannot be classified. |
| kCr50 | Devices with Cr50 firmware. |
| kTi50 | Devices with Ti50 firmware. |

###  Video

| Field | Type | Description |
| ----- | ---- | ----------- |
|  |  | (planned) Video Controller name |
|  |  | (planned) Video RAM (Bytes) |

## Process

##### ProcessInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| command | string | Command which started the process. |
| user_id | uint32 | User the process is running as. |
| priority | int8 | If the process is running a real-time scheduling policy, this field is the negated scheduling priority, minus one. Real-time priorities range from 1 to 99, so this will range from -2 to -100. If the process is not running a real-time scheduling priority, this field will be the raw nice value, where 0 corresponds to the user-visible high priority nice value of -20, and 39 corresponds to the user-visible low priority nice value of 19. |
| nice | int8 | User-visible nice value of the process, from a low priority of 19 to a high priority of -20. |
| uptime_ticks | uint64 | Uptime of the process, in clock ticks. |
| state | [ProcessState](#ProcessState) | State of the process. |
| total_memory_kib | uint32 | Total memory allocated to the process, in KiB. |
| resident_memory_kib | uint32 | Amount of resident memory currently used by the process, in KiB. |
| free_memory_kib | uint32 | Unused memory available to the process, in KiB. This will always be &#124;total_memory_kib&#124; - &#124;resident_memory_kib&#124;. |
| bytes_read | uint64 | The sum of bytes passed to system read calls. This includes terminal I/O and is independent of whether the physical disk is accessed. |
| bytes_written | uint64 | The sum of bytes passed to system write calls. This includes terminal I/O and is independent of whether the physical disk is accessed. |
| read_system_calls | uint64 | Attempted count of read syscalls. |
| write_system_calls | uint64 | Attempted count of write syscalls. |
| physical_bytes_read | uint64 | Attempt to count the number of bytes which this process really did cause to be fetched from the storage layer. |
| physical_bytes_written | uint64 | Attempt to count the number of bytes which this process caused to be sent to the storage layer. |
| cancelled_bytes_written | uint64 | Number of bytes which this process caused to not happen, by truncating pagecache. |
| name | string? | Filename of the executable. |
| parent_process_id | uint32 | PID of the parent of this process. |
| process_group_id | uint32 | Process group ID of the group. |
| threads | uint32 | Number of threads in this process. |
| process_id | uint32 | Process ID of this process. |

##### ProcessState
| Enum | Description |
| ---- | ----------- |
| kUnknown | Unknown. |
| kRunning | The process is running. |
| kSleeping | The process is sleeping in an interruptible wait. |
| kWaiting | The process is waiting in an uninterruptible disk sleep. |
| kZombie | The process is a zombie. |
| kStopped | The process is stopped on a signal. |
| kTracingStop | The process is stopped by tracing. |
| kDead | The process is dead. |
| kIdle | The process is idle. |

## Events

### Usb
| Field | Type | Description |
| ----- | ---- | ----------- |
| vendor | string | Vendor name. |
| name | string | Name, model name, product name. |
| vid | uint16 | Vendor ID. |
| pid | uint16 | Product ID. |
| categories | array&lt;string&gt; | USB device categories. https://www.usb.org/defined-class-codes. |
| state | State | Indicate `kAdd`, `kRemove` event. |

### Thunderbolt
| Field | Type | Description |
| ----- | ---- | ----------- |
| state | State | Indicate `kAdd`, `kRemove`, `kAuthorized`, `kUnAuthorized` event. |

### Lid
| Field | Type | Description |
| ----- | ---- | ----------- |
| state | State | Indicate `kClosed`, `kOpened` event. |

### Bluetooth
| Field | Type | Description |
| ----- | ---- | ----------- |
| state | State | Indicate `kAdapterAdded`, `kAdapterRemoved`, `kAdapterPropertyChanged`, `kDeviceAdded`, `kDeviceRemoved`, `kDevicePropertyChanged` event. |

### Power
| Field | Type | Description |
| ----- | ---- | ----------- |
| state | State | Indicate `kAcInserted`, `kAcRemoved`, `kOsSuspend`, `kOsResume` event. |

### Audio
| Field | Type | Description |
| ----- | ---- | ----------- |
| state | State | Indicate `kUnderrun`, `kSevereUnderrun` event. |

### Audio jack
| Field | Type | Description |
| ----- | ---- | ----------- |
| state | State | Indicate `kAdd`, `kRemove` event. |
| device_type | DeviceType | Indicate `kHeadphone`, `kMicrophone` type. |

### SD card reader
| Field | Type | Description |
| ----- | ---- | ----------- |
| state | State | Indicate `kAdd`, `kRemove` event. |

### Touchpad

##### Touchpad button event
| Field | Type | Description |
| ----- | ---- | ----------- |
| button | [InputTouchButton](#InputTouchButton) | The button corresponds to this event. |
| pressed | bool | True when if the button is pressed. False if the button is released. |

##### InputTouchButton
| Field | Description |
| ----- | ----------- |
| kLeft | Left key. |
| kMiddle | Middle key. |
| kRight | Right key. |

##### Touchpad touch event
| Field | Type | Description |
| ----- | ---- | ----------- |
| touch_points | [array&lt;TouchPointInfo&gt;](#TouchPointInfo) | The touch points reported by the touchpad. |

##### TouchPointInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| tracking_id | uint32 | An id to track an initiated contact throughout its life cycle. |
| x | uint32 | The x position. |
| y | uint32 | The y position. |
| pressure | uint32? | The pressure applied to the touch contact. |
| touch_major | uint32? | The length of the longer dimension of the touch contact. |
| touch_minor | uint32? | The length of the shorter dimension of the touch contact. |

##### Touch connected event
| Field | Type | Description |
| ----- | ---- | ----------- |
| max_x | uint32 | The maximum possible x position of touch points. |
| max_y | uint32 | The maximum possible y position of touch points. |
| max_pressure | uint32 | The maximum possible pressure of touch points, or 0 if pressure is not supported. |
| buttons | [array&lt;InputTouchButton&gt;](#InputTouchButton)

### HDMI
| Field | Type | Description |
| ----- | ---- | ----------- |
| state | State | Indicate `kAdd`, `kRemove` event. |
| display_info | [ExternalDisplayInfo?](#ExternalDisplayInfo) | On Hdmi plug in event, also report information about the newly added display. |

### Touchscreen

##### Touchscreen event
| Field | Type | Description |
| ----- | ---- | ----------- |
| touch_event | [TouchscreenTouchEvent](#TouchscreenTouchEvent) | |
| connected_event | [TouchscreenConnectedEvent](#TouchscreenConnectedEvent) | |

##### TouchscreenTouchEvent
| Field | Type | Description |
| ----- | ---- | ----------- |
| touch_points | [array&lt;TouchPointInfo&gt;](#TouchPointInfo) | The touch points reported by the touchscreen. |

##### TouchscreenConnectedEvent
| Field | Type | Description |
| ----- | ---- | ----------- |
| max_x | uint32 | The maximum possible x position of touch points. |
| max_y | uint32 | The maximum possible y position of touch points. |
| max_pressure | uint32 | The maximum possible pressure of touch points, or 0 if pressure is not supported. |

### Stylus garage
| Field | Type | Description |
| ----- | ---- | ----------- |
| state | State | Indicate `kInsert`, `kRemove` event. |

### Stylus

##### Stylus event
| Field | Type | Description |
| ----- | ---- | ----------- |
| touch_event | [StylusTouchEvent](#StylusTouchEvent) | |
| connected_event | [StylusConnectedEvent](#StylusConnectedEvent) | |

##### StylusTouchEvent
| Field | Type | Description |
| ----- | ---- | ----------- |
| touch_point | [StylusTouchPointInfo?](#StylusTouchPointInfo) | The info of the stylus touch point. A null touch point means the stylus leaves the contact. |

##### StylusTouchPointInfo
| Field | Type | Description |
| ----- | ---- | ----------- |
| x | uint32 | The x position. |
| y | uint32 | The y position. |
| pressure | uint32? | The pressure applied to the touch contact. |

##### StylusConnectedEvent
| Field | Type | Description |
| ----- | ---- | ----------- |
| max_x | uint32 | The maximum possible x position of touch points. |
| max_y | uint32 | The maximum possible y position of touch points. |
| max_pressure | uint32 | The maximum possible pressure of touch points, or 0 if pressure is not supported. |

### Crash
| Field | Type | Description |
| ----- | ---- | ----------- |
| crash_report_id | string | Corresponding to "upload_id" in uploads.log. |
| creation_time | ash.cros_healthd.external.mojo_base.mojom.Time | The creation time of the uploads.log file. Used to distinguish uploads.log file in case it has been deleted and recreated. |
| offset | uint64 | Number of valid logs before this event in uploads.log. Useful to inform subscribers that need to distinguish whether a crash event has been encountered before. |
