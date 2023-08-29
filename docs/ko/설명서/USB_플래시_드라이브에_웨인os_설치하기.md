## 참고
이 문서는 여러분의 기여(문서 작성, 번역, 보고, 제안, 코딩)를 기다리고 있습니다.

## 1. 준비 사항
- OS 이미지 파일과 동일한 디스크 여유 공간이 있는 Windows/Linux/Chromebook PC
- USB 플래시 드라이브

## 2. [웨인OS 바이너리 다운로드](https://wayne-os.com/download-wayne-os-binary/)

## 3. USB 플래시 드라이브 초기화 (선택 사항)
- USB 플래시 드라이브에 오류/손상이 있는 경우 설치 프로세스가 실패할 수 있습니다.
- [Initialize USB](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/initializing_usb_flash_drive.md)

## 4. 이미지 라이터 도구로 USB 플래시 드라이브에 .bin 파일 쓰기 ### Windows 사용자
- _USBWriter-1.3_: [download](https://sourceforge.net/projects/usbwriter/)
- _win32diskimager-binary_: [download](https://win32diskimager.download/)
- _Chromebook recovery utility_: [download](https://chrome.google.com/webstore/detail/chromebook-recovery-utili/jndclpdbaamdhonoechobihbbiimdgai/RK%3D2/RS%3DUI2uA8SxDAwF_T9oPb4YviZFT3Y-)
<br>우측 상단의 톱니바퀴 아이콘/설정 > 로컬 이미지 사용을 클릭합니다.
- _balenaEtcher-Portable-1.5.109_: 웨인OS 설치에서 완벽하게 작동하지 않는 것 같습니다.
- _rufus-3.11_: 웨인OS를 정확히 설치할 수 없음

### 크롬북사용자
- _Chromebook recovery utility_: [download](https://chrome.google.com/webstore/detail/chromebook-recovery-utili/jndclpdbaamdhonoechobihbbiimdgai/RK%3D2/RS%3DUI2uA8SxDAwF_T9oPb4YviZFT3Y-)

### 리눅스 사용자
`$ sudo dd if=${BIN_FILE} of=/dev/${USB_FLASH_DRIVE}`
<br>
`${BIN_FILE}` 은 wayne-os-usb16g-1q21.bin과 같은 .bin 파일 이름이어야 합니다.
<br>
`${USB_FLASH_DRIVE}` 는 sdx1과 같은 파티션 이름이 아니라 sdx와 같은 장치 이름이어야 합니다.
<br>
**경고: 로컬 저장소(예: HDD/SSD) 이름을 실수로 쓰면 로컬 저장소의 데이터가 손실되므로 `lsblk`로 장치 이름을 주의 깊게 확인하시기 바랍니다.**
<br>

## 5. 확인
-wayne-os-portable_ 버전을 설치한 경우, 설치에 성공하면 Windows/macOS에서 STORAGE 파티션만 확인할 수 있습니다.
- Try to boot the USB flash drive on your computer via USB booting from BIOS/UEFI setting
