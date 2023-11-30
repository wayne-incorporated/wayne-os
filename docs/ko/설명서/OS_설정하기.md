## GUI 설정 (중요한 설정들만 명시)
#### 디바이스가 유휴상태일 때도 화면을 켜두기
1. Settings (화면 우측 하단 클릭 > 톱니바퀴 클릭)
2. Device
3. Power
4. When idle: Keep display on
#### 한국어 입력하기
1. Settings (화면 우측 하단 클릭 > 톱니바퀴 클릭)
2. Device
3. Keyboard
4. Change input settings
5. Show input options in the shelf: on
6. Input methods: Hangul 2 Set
7. 키보드 입력 시, ctrl+space 로 한영 전환
8. on screen keyboard 입력 시, 화면 우측 하단 Input methods 아이콘을 클릭하여 한글로 전환
#### 알림 끄기
1. Settings (화면 우측 하단 클릭 > 톱니바퀴 클릭)
2. Apps
3. Notifications: Do not disturb on
4. Apps
5. Restore apps on startup: off

## CUI 설정

#### wayne-autologin.conf 편집하기 (설정 스크립트 문제 발생 시 사용)
- [콘솔 모드 진입](https://github.com/Wayne-Incorporated/wim-os/blob/main/docs/using_shell.md) 후, `sudo mount -o remount,rw / && sudo vi /etc/init/wayne-autologin.conf`
- autologin.py 의 --url 파라미터를 변경

#### chrome_dev.conf 편집하기 (설정 스크립트 문제 발생 시 사용)
- [콘솔 모드 진입](https://github.com/Wayne-Incorporated/wim-os/blob/main/docs/using_shell.md) 후, `sudo mount -o remount,rw / && sudo vi /etc/chrome_dev.conf`
- Chromium 모드 flag 리스트(https://peter.sh/experiments/chromium-command-line-switches/) 를 참조하여, 해당 기능을 기입하기
- `chrome_dev.conf`파일 저장 후, 재부팅
- 적용 가능한 기능:
- --kiosk: 웹 브라우저를 전체화면으로 실행. 웹 브라우저 및 전원버튼을 제외한 모든 기능이 잠김
- --start-fullscreen: 웹 브라우저가 전체화면으로 실행. 패널, [셸](https://github.com/wayne-incorporated/wim-os/blob/main/docs/%EC%85%B8%20%EC%82%AC%EC%9A%A9%ED%95%98%EA%B8%B0.md) 등의 기능 사용 가능
- --enable-virtual-keyboard: 터치 스크린용 키보드
- --incognito: 웹 브라우저가 익명모드로 실행
