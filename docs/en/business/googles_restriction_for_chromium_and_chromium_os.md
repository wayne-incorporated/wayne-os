## Issue
Unfortunately since 2021-03-15, Google mentioned they will restrict their Oauth & Chrome Sync on Chromium and Chromium OS which are made by third-parties.
<br>
It means that in Wayne OS, login by Google ID will be rate limited and Chromium browser will not be synced with Google ID.
<br>
This is not only affect to Wayne OS as there are various browsers/OSs/embedded-SWs are from open source Chromium & Chromium OS project, which have spread Google service and grown up together in the open source environment. However Google seems to decide to take their share against rivals now.

## Solution
Different from Chromium, Chromium OS requires Google login to use. Google therefore allows the login in Chromium OS with whitelist.
<br>https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/signing_in_google_account_in_wayne_os.md

## Reference
https://blog.chromium.org/2021/01/limiting-private-api-availability-in.html
<br>
https://groups.google.com/a/chromium.org/g/chromium-packagers/c/SG6jnsP4pWM
<br>
https://www.omgubuntu.co.uk/2021/01/chromium-sync-google-api-removed
<br>
https://alien.slackbook.org/blog/how-to-un-google-your-chromium-browser-experience/#comments
