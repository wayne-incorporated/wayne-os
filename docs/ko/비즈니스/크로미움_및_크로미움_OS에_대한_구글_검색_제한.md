## 노토
원본 문서: [googles_restriction_for_chromium_and_chromium_os.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/business/googles_restriction_for_chromium_and_chromium_os.md)

## 문제
아쉽게도 2021-03-15부터 구글은 타사에서 만든 크롬과 크롬 OS에서 Oauth 및 크롬 동기화를 제한할 것이라고 언급했습니다.
<br>
즉, 웨인 OS에서는 구글 아이디로 로그인하는 속도가 제한되고 크롬 브라우저는 구글 아이디와 동기화되지 않습니다.
<br>
오픈소스 환경에서 구글 서비스를 확산시키고 함께 성장해 온 크롬 및 크롬 OS 프로젝트에는 다양한 브라우저/OS/임베디드-SW가 존재하기 때문에 이는 웨인 OS에만 영향을 미치는 것은 아닙니다. 하지만 구글은 이제 경쟁자들과의 점유율 경쟁에 나선 것으로 보입니다.

## 해결책
크롬과 달리 크롬 OS를 사용하려면 구글 로그인이 필요합니다. 따라서 Google은 화이트리스트를 통해 Chromium OS에서 로그인을 허용합니다.
<br>https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/signing_in_google_account_in_wayne_os.md

## 참조
https://blog.chromium.org/2021/01/limiting-private-api-availability-in.html
<br>
https://groups.google.com/a/chromium.org/g/chromium-packagers/c/SG6jnsP4pWM
<br>
https://www.omgubuntu.co.uk/2021/01/chromium-sync-google-api-removed
<br>
https://alien.slackbook.org/blog/how-to-un-google-your-chromium-browser-experience/#comments
