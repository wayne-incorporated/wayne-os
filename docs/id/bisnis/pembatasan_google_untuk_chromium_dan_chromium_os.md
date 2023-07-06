## Catatan
Dokumen asli: [googles_restriction_for_chromium_and_chromium_os.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/business/googles_restriction_for_chromium_and_chromium_os.md)

## Isu
Sayangnya sepeti yang disebutkan oleh Google bahwa sejak 15-03-2021, mereka akan membatasi sistem Oauth & Chrome Sync di Chromium dan Chromium OS yang dibuat oleh pihak ketiga.
<br>
<br>
Sebagaimana disebutkan berarti , login dengan Google ID akan dibatasi dan browser Chromium tidak bisa sinkronisasi dengan Google ID di Wayne OS.
<br>
<br>
Hal ini tidak hanya akan berpengaruh kepada Wayne OS dikarenakan berbagai macam browser/OS/perankat lunak yang berasal dari projek open source Chromium & Chromium OS project, yang telah menyebarkan servis Google dan berkembang bersama dalam lingkungan open source. Namun, Google sepertinya memutuskan untuk mengambil bagian dari para saingan mereka.

## Solusi
Berbeda dari Chromium, Chromium OS membutuhkan login Google untuk digunakan. Oleh karena itu, Google mengizinkan login di Chromium OS dengan whitelist.
<br>https://github.com/wayne-incorporated/wayne-os/blob/main/docs/id/tata-cara/memasukkan_akun_google_di_wayne_os.md

## Referensi
https://blog.chromium.org/2021/01/limiting-private-api-availability-in.html
<br>
https://groups.google.com/a/chromium.org/g/chromium-packagers/c/SG6jnsP4pWM
<br>
https://www.omgubuntu.co.uk/2021/01/chromium-sync-google-api-removed
<br>
https://alien.slackbook.org/blog/how-to-un-google-your-chromium-browser-experience/#comments
