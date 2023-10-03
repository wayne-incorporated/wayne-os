## 노트
원본 문서: [installing_wayne_os_on_a_pc.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/installing_wayne_os_on_a_pc.md)
<br>이 문서는 당신의 기여(문서화, 번역, 신고, 제안, 코딩)를 기대합니다.
<br>_wayne-os-dev_ 와 _wayne-os-test_ 버전만 PC설치를 지원하며, _wayne-os-base_ 버전은 PC 설치를 지원하지 않습니다.

## 1. 준비
- _wayne-os-dev_ 혹은 _wayne-os-test_ 버전을 [USB flash drive에 설치](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/ko/%EC%84%A4%EB%AA%85%EC%84%9C/USB_%ED%94%8C%EB%9E%98%EC%8B%9C_%EB%93%9C%EB%9D%BC%EC%9D%B4%EB%B8%8C%EC%97%90_%EC%9B%A8%EC%9D%B8os_%EC%84%A4%EC%B9%98%ED%95%98%EA%B8%B0.md)하세요.
- 설치할 PC에서 USB flash drive를 통해 웨인 OS를 부팅하신 후, 올바른 작동 여부를 확인하세요 (HW 호환성, 기능, 알려진 문제점).
<p>이 때 에러가 발생하면, PC에 설치 후에도 같은 에러가 발생합니다. 이 경우 PC 설치를 재고 하시는 것이 좋습니다.
<br>참고로 PC설치 후, 웨인OS의 STATE 파티션 용량은 로컬 디스크 용량만큼 늘어납니다.

## 2. 설치
- [콘솔 모드에 로그인](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/ko/%EC%84%A4%EB%AA%85%EC%84%9C/%EC%85%B8_%EC%82%AC%EC%9A%A9%ED%95%98%EA%B8%B0.md)하세요.
- `lsblk`를 통해 디스크 이름 확인을 하세요.
<br>**`lsblk`화면에서 _SIZE_ 와 _TYPE_ 열을 확인 후 신중히 디스크를 선택하세요**
<br>**파티션 이름 (ex: sda1 8:1 0 55.3G 0 part) 이 아닌, 정확한 디스크명 (ex: sda 8:0 0 59.6G 0 disk) 을 선택하세요.**
<br>**웨인OS를 설치할 디스크와 다른 로컬/이동식 디스크를 혼동하지 마세요. 웨인OS 설치 후 해당 디스크의 모든 데이터는 사라집니다.**
- `sudo /usr/sbin/chromeos-install --dst /dev/${TARGET_DISK}` 를 입력하세요.
<br>(ex: `sudo /usr/sbin/chromeos-install --dst /dev/sda`)
- 콘솔이 비밀번호를 물어보면 입력하세요.
- 십여분 후 설치가 성공하면 `Installation to /dev/${TARGET_DISK} complete. Please shutdown, remove the USB device, cross your fingers, and reboot.` 메시지를 볼 수 있습니다.
- `sudo poweroff` 를 통해 PC 전원을 끄고, USB flash drive를 제거하세요, 그리고 설치된 디스크로 [웨인OS를 부팅](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/ko/%EC%84%A4%EB%AA%85%EC%84%9C/%EC%9B%A8%EC%9D%B8os_%EB%B6%80%ED%8C%85.md)하세요.

## 3. 문제 해결
- 이동식 디스크에 웨인 OS를 설치하려면, `--skip_dst_removable` 를 추가하세요.
<br> (ex: `sudo /usr/sbin/chromeos-install --skip_dst_removable --dst /dev/sda`)
- `sudo /usr/sbin/chromeos-install --help` 는 더 많은 옵션들을 보여줍니다.
- `sudo dd if=/dev/zero bs=512 count=4096 of=/dev/${TARGET_DISK}` 는 파티션 구조를 삭제하고 타깃 디스크를 초기화합니다.
