## 노토
원본 문서: [commands_for_os_management.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/commands_for_os_management.md)

## 참고
이 문서는 여러분의 기여(문서화, 번역, 보고, 제안, 코딩)를 기다리고 있습니다.
<br>할 일: 이 문서는 다른 CROS 파생 문서에서도 작동하는 것 같으므로 테스트 결과를 추가해야 합니다.
<br>이 문서는 웨인OS를 관리하고자 하는 개발자에게 도움이 되고자 합니다.

## 요구 사항
wayne-os-dev_ 또는 _wayne-os-test_ 버전

## 로컬 셸에서
웨인OS 기기에서 [셸 열기](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/ko/%EC%84%A4%EB%AA%85%EC%84%9C/%EC%85%B8_%EC%82%AC%EC%9A%A9%ED%95%98%EA%B8%B0.md)를 실행한 후 다음 단계를 시도합니다.
#### 파워워시
```
$ { sudo bash -c 'echo "fast safe" > /mnt/stateful_partition/factory_install_reset' ;} && sudo reboot
```
또는
```
$ { echo "fast safe" | sudo tee -a /mnt/stateful_partition/factory_install_reset ;} && sudo reboot
```
#### 작업 제어
웨인OS 및 크롬 OS 파생 프로그램은 [업스타트](https://upstart.ubuntu.com/)를 사용합니다.
작업 목록을 확인하려면.
```
sudo initctl list
```
작업을 제어하려면.
```
sudo initctl start/stop/restart/status ${JOB}
```

#### 정보, 성능 확인에 사용할 수 있는 명령어
- cat [/proc/*](https://man7.org/linux/man-pages/man5/proc.5.html)
- cat /etc/*release
- [lscpu](https://man7.org/linux/man-pages/man1/lscpu.1.html)
- [lsusb](https://man7.org/linux/man-pages/man8/lsusb.8.html)
- sudo [lspci](https://man7.org/linux/man-pages/man8/lspci.8.html)
- [mount](https://man7.org/linux/man-pages/man8/mount.8.html)
- [uname](https://man7.org/linux/man-pages/man1/uname.1.html)
- [ifconfig](https://man7.org/linux/man-pages/man8/ifconfig.8.html)
- [top](https://man7.org/linux/man-pages/man1/top.1.html)
- [free](https://man7.org/linux/man-pages/man1/free.1.html)
- [vmstat](https://man7.org/linux/man-pages/man8/vmstat.8.html)
- [netstat](https://man7.org/linux/man-pages/man8/netstat.8.html)
- [df](https://man7.org/linux/man-pages/man1/df.1.html)
- [du](https://man7.org/linux/man-pages/man1/du.1.html)
- [lsof](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [uptime](https://man7.org/linux/man-pages/man1/uptime.1.html)
- [ps](https://man7.org/linux/man-pages/man1/ps.1.html)
- [pmap](https://man7.org/linux/man-pages/man1/pmap.1.html)
- sudo [ss](https://man7.org/linux/man-pages/man8/ss.8.html)
- [ipcs](https://man7.org/linux/man-pages/man1/ipcs.1.html)
- sudo [dmidecode](https://linux.die.net/man/8/dmidecode)
- sudo [hdparm](https://man7.org/linux/man-pages/man8/hdparm.8.html)
- [lsblk](https://man7.org/linux/man-pages/man8/lsblk.8.html)
- sudo [dmesg](https://man7.org/linux/man-pages/man1/dmesg.1.html)

## 원격에서
[ssh](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/ko/%EC%84%A4%EB%AA%85%EC%84%9C/%EC%9B%90%EA%B2%A9%EC%97%90%EC%84%9C__ssh_%EC%97%B0%EA%B2%B0.md)를 통해 원격 장치에서 웨인OS 장치로 셸 명령을 보낼 수 있습니다.
```
ssh chronos@${IP} -t "COMMAND" # 명령에 sudo가 포함되어 있는지 pw에게 다시 묻습니다.
ssh root@${IP} "COMMAND" # 이 명령은 Wayne OS 테스트 버전에서만 사용할 수 있습니다.
```

#### 예제
- 웨인OS 장치에 강제 파워워시.
```
$ ssh chronos@192.168.100.200 -t "{ echo "fast safe" | sudo tee -a /mnt/stateful_partition/factory_install_reset ;} && sudo reboot"
```
- 웨인OS 장치에서 UI(로그아웃 사용자 그래픽 세션)를 강제로 다시 시작합니다.
```
$ ssh root@192.168.100.200 "initctl restart UI"
```
- 웨인OS 장치에서 프로세스 정보를 가져옵니다.
```
$ ssh chronos@192.168.100.200 -t "top -n 1 -b" > proc_list.txt
```
