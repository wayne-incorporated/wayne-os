## 사용 방법
PC/기기/칩셋 이름을 검색(`ctrl+f`)하고 호환성 정보를 확인합니다.

## 보고/기여 방법
### 간단한 방법
호환성 표를 참고하여 커뮤니티에 HW 호환성 문제를 보고해 주세요.
호환성 표를 참조하여 문제를 자세히 작성해 주시면 감사하겠습니다.
그러면 다른 기여자/관리자가 이 문서에 귀하의 이름/ID와 함께 문제를 작성합니다.

### 더 나은 방법
오픈 소스 정신이 있다면 누구나 기여자가 될 수 있습니다.
1) [웨인 OS 프로젝트에 참여](https://gitlab.com/wayne-inc/wayneos/-/blob/master/CONTRIBUTING.md)하고 _개발자_ 역할을 받습니다.
2) 임시 브랜치를 생성합니다(예: report-hw_compatibility-[date]).
3) *docs/release/hw_compatibility_information.md*에 HW 호환성 정보를 추가합니다.
4) 커밋
5) 임시 브랜치(예: report-hw_compatibility-[date]) 브랜치에서 마스터 브랜치로 Merge Request를 보냅니다.
6) 임시 브랜치 삭제 (선택 사항)

## 호환성 표
PC: 디바이스가 포함된 상세 PC 이름입니다. 구분 기호는 공백(빈칸)이어야 검색이 쉬워집니다.
카테고리
프로세서: CPU그래픽: 내장/외장 GPU, 밝기 조절
무선랜: 와이파이, IEEE 802.11
이더넷: 케이블 포함 LAN
I/O 포트: 입력/출력 포트/인터페이스
입력 장치: 키보드, 마우스, 터치패드
오디오: 오디오 입력/출력, 볼륨 조절
버튼: 컴퓨터의 전원/절전/기타 버튼
블루투스
카메라
기타: 카테고리는 더 추가될 수 있습니다.

장치: 검사한 장치 이름의 세부 정보입니다. 구분 기호는 검색을 쉽게 하기 위해 공백(빈칸)이어야 합니다.
칩셋/드라이버: 장치의 세부 칩셋/드라이버 이름입니다. 구분 기호는 공백(빈칸)이어야 검색이 용이합니다.
작동
    - O: 완벽하게 작동
    - !: 문제 있음
    - X: 전혀 작동하지 않음
증상: _works_ 열에 대한 설명
OS 버전: Wayne OS 버전(예: _test-installation-3q21_)
보고자: 익명/이름/ID/닉네임/이메일
보고 날짜: YYYY-MM-DD
비고: 추가 정보

| PC | 카테고리 | 장치 | 칩셋<br>/드라이버 | 작동 방식 | 증상 | OS 버전 | 보고자 | 보고 날짜 | 비고 |
| --- | --- | ---  | --- | :---: | --- | --- | --- | --- | --- |
||wlan|tp-ink ac600 Archer T2U Plus|Realtek RTL8811AU|X||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|tp-ink ac600 Archer T2U v3|Realtek RTL8811AU|X||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|NEXT 501AC MINI|Realtek RTL8821CU|X||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|Nexi NX1131 NX-AC600BT R-R-RN7-NX-1131|Realtek RTL8821CU|X||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|Iptime A1000U|MediaTek MT7610U|X||3q21-r1|Wayne Inc.|2021-11-26|Wayne OS는 2022년부터 이 모델을 지원할 예정입니다. CloudReady(커널 5.4)에서 이 모델 지원|
||wlan|Iptime A1000 mini|MediaTek MT7610U|X||3q21-r1|Wayne Inc.|2021-11-26|Wayne OS는 2022년부터 이 모델을 지원할 예정입니다|
||wlan|Iptime A1000 mini AU|MediaTek MT7610U|X||3q21-r1|Wayne Inc.|2021-11-26|Wayne OS는 2022년부터 이 모델을 지원할 예정입니다|
||wlan|Iptime G054UA|Ralink RT2501/RT2573 RT73 RT2571|O||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|Iptime n100 mini|Realtek RTL8188CU|O||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|Nexi NX-AC1300|Realtek RTL8812BU|X||3q21-r1|Wayne Inc.|2021-11-26||
||wlan|Nexi NX-AC600 NX1130|Realtek RTL8811CU|X||3q21-r1|Wayne Inc.|2021-11-26||
이 장치에서는 |Asus Transformer Book T100TA|wlan|Broadcom 802.11 abgn Wireless SDIO Adapter||X||3q21-r1|Stepan Rumyantsev|2021-10-30|CloudReady(커널 5.4) 및 Fedora(버전 34)가 정상적으로 작동합니다|
||wlan|Intel Centrino Wireless N 100|Intel iwlwifi|X||3q21|Donna R Marpaung|2021-08-14|v: kernel port: d000 bus ID: 03:00.0 chip ID: 8086:08ae IF: wlp3s0 state: up mac: \<filter\>|
|ASUSTeK K43SD|wlan|Qualcomm Atheros AR8151 v2.0 Gigabit Ethernet|atl1c|X||3q21|Donna R Marpaung|2021-08-14|v: 1.0.1.1-NAPI port: 9000 bus ID: 05:00.0 chip ID: 1969:1083 IF: enp5s0 state: down mac: \<filter\> v: 1.0 serial: <filter> Mobo: ASUSTeK model: K43SD v: 1.0 serial: <filter> UEFI: American Megatrends  v: K43SD.208 date: 08/10/2012|
|Dell Inspiron 15 3501||||X|cannot boot|3q21|Ifty ER|2021-08-05|CPU/GPU 호환성이 의심됩니다|
|Dell Inspiron 14 3467|wlan|||X||1q21|Jesus Daniel CJ|2021-05-14||
|Samsung NT 670Z5E X58S|wlan|||X||1q21|Choi Jaehyuk|2021-05-04||
|E4300|Graphic|Graphic Card Intel GMA 4500MHD||X|흰색 화면이 표시된 후 검은색이 표시됨|1q21|Peter Nimmo|2021-05||
|E4300|input device|Alps PS/2 ALPS DualPoint Stick||O||1q20|Peter Nimmo|2021-05|as /devices/platform/i8042/serio1/input/input7|
|E4300|input device|Alps PS/2 ALPS DualPoint TouchPad||!|1q20|Peter Nimmo|2021-05|as /devices/platform/i8042/serio1/input/input6<br><br>터치패드가 작동하려면 부팅 중에 커널에 "psmouse.proto=imps"를 통과해야 합니다|.
|M1210|graphic|Intel Graphics Media Accelerator 950 (integrated)||X|흰색 화면이 표시된 후 검은색이 표시됨|1q21|Peter Nimmo|2021-05||
|M1210|input device|Synaptics TouchPad||O||2q20|Peter Nimmo|2021-05||
||graphic|AMD E1 6010 APU with AMD Radeon R2 Graphics||X|설치 후 화면이 검은색이었습니다|usb16g-1q21|Nickatnyte Chauhan|2021-04-01||

#### 표 규칙
영어로 관리
최신 정보는 표 위에 추가합니다.
한 행에는 디바이스/OS 버전에 대한 정보가 하나씩 포함됩니다.
기존 정보에 동의하지 않는 경우 기존 정보를 삭제/수정하는 대신 표에 다른 행을 추가합니다.
