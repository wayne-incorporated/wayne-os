## How to use
Search (`ctrl+f`) your PC/device/chipset name, and check the compatibility information

## How to report/contribute
#### Simple way
Refer to compatibility table, and report HW compatibility issue on [community](https://www.facebook.com/groups/wayneosgroup). 
<br>We would appreciate it if you write the issue in detail by referring to the _Compatibility table_.
<br>Then other contributors/maintainers would write the issue on this document with your name/ID.

#### Better way
If you have open source spirit, you can be a contributor.
1) [Join Wayne OS project](https://github.com/wayne-incorporated/wayne-os/blob/main/CONTRIBUTING.md) and get _Developer_ role
2) Make a temporary branch (ex: report-hw_compatibility-[date])
3) Add HW compatibility information on *docs/release/hw_compatibility_information.md*
4) Commit
5) Send a merge request from the temporary branch (ex: report-hw_compatibility-[date]) branch to master branch
6) Remove the temporary branch (optional)

## Compatibility table
- PC: a detail PC name with device. The delimiter should be a space (blank) for easier searching
- category
    - processor: CPU
    - graphic: integrated/external GPU, brightness control
    - wlan: WiFi, IEEE 802.11
    - ethernet: LAN with cable
    - I/O port: input/output ports/interface
    - input device: keyboard, mouse, touchpad
    - audio: audio input/output, volume control
    - buttons: power/sleep/etc buttons on computer
    - bluetooth
    - camera
    - etc: category could be added more
- device: a detail of inspected device name. The delimiter should be a space (blank) for easier searching
- chipset/driver: a detail chipset/driver name of the device. The delimiter should be a space (blank) for easier searching
- works
    - O: working perfectly
    - !: working with problem
    - X: not working at all
- symptom: description for _works_ column
- OS version: Wayne OS version (ex: _test-installation-3q21_)
- reporter: anonymous/name/ID/nickname/email
- report date: YYYY-MM-DD
- remark: additional information

#### Desktop PC
#### Laptop PC
#### ETC

| PC | category | device | chipset<br>/driver | works | symptom | OS version | reporter | report date | remark |
| --- | --- | ---  | --- | :---: | --- | --- | --- | --- | --- |
||wlan|tp-ink ac600 Archer T2U Plus|Realtek RTL8811AU|X||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|tp-ink ac600 Archer T2U v3|Realtek RTL8811AU|X||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|NEXT 501AC MINI|Realtek RTL8821CU|X||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|Nexi NX1131 NX-AC600BT R-R-RN7-NX-1131|Realtek RTL8821CU|X||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|Iptime A1000U|MediaTek MT7610U|X||3q21-r1|Wayne Inc.|2021-11-26|Wayne OS would support this model since 2022. CloudReady (kernel 5.4) support this model|
||wlan|Iptime A1000 mini|MediaTek MT7610U|X||3q21-r1|Wayne Inc.|2021-11-26|Wayne OS would support this model since 2022|
||wlan|Iptime A1000 mini AU|MediaTek MT7610U|X||3q21-r1|Wayne Inc.|2021-11-26|Wayne OS would support this model since 2022|
||wlan|Iptime G054UA|Ralink RT2501/RT2573 RT73 RT2571|O||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|Iptime n100 mini|Realtek RTL8188CU|O||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|Nexi NX-AC1300|Realtek RTL8812BU|X||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|Nexi NX-AC600 NX1130|Realtek RTL8811CU|X||3q21-r1|Wayne Inc.|2021-11-26||
|Asus Transformer Book T100TA|wlan|Broadcom 802.11 abgn Wireless SDIO Adapter||X||3q21-r1|Stepan Rumyantsev|2021-10-30|CloudReady (kernel 5.4) and Fedora (version 34) work well about this device|
||wlan|Intel Centrino Wireless N 100|Intel iwlwifi|X||3q21|Donna R Marpaung|2021-08-14|v: kernel port: d000 bus ID: 03:00.0 chip ID: 8086:08ae IF: wlp3s0 state: up mac: \<filter\>|
|ASUSTeK K43SD|wlan|Qualcomm Atheros AR8151 v2.0 Gigabit Ethernet|atl1c|X||3q21|Donna R Marpaung|2021-08-14|v: 1.0.1.1-NAPI port: 9000 bus ID: 05:00.0 chip ID: 1969:1083 IF: enp5s0 state: down mac: \<filter\> v: 1.0 serial: <filter> Mobo: ASUSTeK model: K43SD v: 1.0 serial: <filter> UEFI: American Megatrends  v: K43SD.208 date: 08/10/2012|
|Dell Inspiron 15 3501||||X|cannot boot|3q21|Ifty ER|2021-08-05|CPU/GPU compatibility is suspected|
|Dell Inspiron 14 3467|wlan|||X||1q21|Jesus Daniel CJ|2021-05-14||
|Samsung NT 670Z5E X58S|wlan|||X||1q21|Choi Jaehyuk|2021-05-04||
|E4300|graphic|Graphics Card Intel GMA 4500MHD||X|shows a white screen, then black|1q21|Peter Nimmo|2021-05||
|E4300|input device|Alps PS/2 ALPS DualPoint Stick||O||1q20|Peter Nimmo|2021-05|as /devices/platform/i8042/serio1/input/input7|
|E4300|input device|Alps PS/2 ALPS DualPoint TouchPad||!||1q20|Peter Nimmo|2021-05|as /devices/platform/i8042/serio1/input/input6<br><br>it needed to pass "psmouse.proto=imps" to the kernel during boot for the touchpad to work|
|M1210|graphic|Intel Graphics Media Accelerator 950 (integrated)||X|shows a white screen, then black|1q21|Peter Nimmo|2021-05||
|M1210|input device|Synaptics TouchPad||O||2q20|Peter Nimmo|2021-05||
||graphic|AMD E1 6010 APU with AMD Radeon R2 Graphics||X|screen was black after installation|usb16g-1q21|Nickatnyte Chauhan|2021-04-01||

#### Rules for table
- Manage in English
- Add the newest information on top of the table
- One row includes one information for a device/OS-version
- If you don't agree about the existing information, add another row in table, instead of deleting/modifying the existing information
