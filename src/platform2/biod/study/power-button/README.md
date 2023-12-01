# Power-button FPS Study

This folder contains scripts and resources used for the "power-button study".

The goal is to analyze the interaction between co-located fingerprint sensor
and power button.

## Installation

* Press Ctrl + Alt + T to open ChromeOS Developer Shell
* Run `shell` to open the command line shell
* Enter the Downloads folder: `cd ~/Downloads`
* Download the latest version of the script

```
curl "https://chromium.googlesource.com/chromiumos/platform2/+/main/biod/study/power-button/filtered_logs.sh?format=TEXT"| base64 --decode > filtered_logs.sh
```

## Usage

* Enter the Download folder `cd ~/Downloads`
* Run the script: `bash filtered_logs.sh`
