## 노트
원본 문서: [bi_change.md](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/bi_change.md)
<br>이 문서는 당신의 기여(문서화, 번역, 신고, 제안, 코딩)를 기대합니다.<br>[웨인 OS 라이선스](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/ko/%EB%B9%84%EC%A6%88%EB%8B%88%EC%8A%A4/%EC%9D%B4%EC%9A%A9%EC%95%BD%EA%B4%80.md)하에, 웨인OS는 유저/고객들이 BI (brand idendity: 로고, 이름)를 어떤 목적으로든 (ex: 내부사용, 배포, 판매) 변경하는 것을 허가합니다. 

## 준비
- [chromiumos-assets](https://gitlab.com/wayne-inc/wayneos/-/tree/master/src/platform/chromiumos-assets) 패키지를 참고하여 _png_ 이미지 파일을 준비하세요.
- _png_ 파일의 픽셀 사이즈와 파일명이 참고자료와 동일한 지 확인하세요.

## Putting your BI in Wayne OS
- [콘솔 모드에 로그인](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/ko/%EC%84%A4%EB%AA%85%EC%84%9C/%EC%85%B8_%EC%82%AC%EC%9A%A9%ED%95%98%EA%B8%B0.md)하세요.
- 다음 경로에 존재하는 파일들을 삭제하세요.
<br>/usr/share/chromeos-assets/images
<br>/usr/share/chromeos-assets/images_100_percent
<br>/usr/share/chromeos-assets/images_200_percent
- Put your image files in above path (via USB flash drive or ssh)
- 당신의 이미지 파일들을 상기 경로에 넣으세요 (USB flash drive 혹은 ssh 이용).
- 재부팅 후 새로운 BI를 확인하세요.
