## 참고
이 문서는 여러분의 기여(문서 작성, 번역, 보고, 제안, 코딩)를 기다리고 있습니다.

## 요구 사항
- 서버: _dev_ 또는 _test_ 버전을 실행하는 웨인 OS PC
- 클라이언트: ssh 클라이언트 기능이 있는 PC (모든 OS 괜찮지만, 이 문서에서는 리눅스 셸로 설명합니다.)
- 서버의 IP 주소를 확인하고 클라이언트에서 해당 IP에 연결할 수 있는지 확인합니다(예: `ping ${SERVER_IP}`).

## 웨인 OS 개발 버전
#### 클라이언트에서 서버에 연결
ID: chronos
<br>PW: _wayne-os-dev_ 버전의 비밀번호
- 예시
~~~
$ ssh chronos@192.168.140.172
Password:
~~~
#### 비밀번호 생략 
TODO: write

## Wayne OS 테스트 버전
#### 1. 클라이언트에서 설정
먼저, 테스트 RSA 키와 구성 파일을 ~/.ssh/에 다운로드합니다.
~~~
$ cd ~/.ssh && wget \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/testing_rsa \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/testing_rsa.pub \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/config
~~~
그런 다음 ~/.ssh/testing_rsa에 대한 권한을 제한합니다.
~~~
chmod 0600 ~/.ssh/testing_rsa
~~~
그리고 _000.000.000.000_을 편집기로 _config_ 파일에서 클라이언트의 IP 주소로 바꿉니다.

$ vim ~/.ssh/config
~~~
~~~
# 예제
호스트 wayne-os
  CheckHostIP no
  StrictHostKeyChecking 아니요
  IdentityFile %d/.ssh/testing_rsa
  프로토콜 2
  사용자 루트
  호스트 이름 000.000.000.000 # 여기서 서버 IP로 바꾸기
~~~

#### 2. 클라이언트에서 서버에 연결
~~~
$ ssh wayne-os
~~~
그러면 비밀번호가 없는 루트 셸이 나타납니다.
<br>여러 서버에 연결할 경우 ~/.ssh/config에서 공통 구성 옵션을 공유할 수 있습니다.
~~~
# 예시
Host 172.22.168.* # 서버가 포함된 서브넷
CheckHostIP 없음
StrictHostKeyChecking 없음
  IdentityFile %d/.ssh/testing_rsa
  Protocol 2
  User root

Host wayne-os1
  호스트 이름 172.22.168.233 #여기에 서버 IP 쓰기

Host wayne-os2
  호스트 이름 172.22.168.234 #여기에 서버 IP 쓰기
~~~

## 참조
https://www.chromium.org/chromium-os/testing/autotest-developer-faq/ssh-test-keys-setup
