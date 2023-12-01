# Post-profiling coverage generation script

This post-processing script automates the whole procedure of collecting raw profiles, generating index profdatas from DUT(s) for multiple packages. It finally generates coverage report in html format for each file,for each provided package. Additionally, it supports exclusion of unwanted files from the coverage report.
Please run `./gencov.py -h` to know the command line arguments for this script.

Sample usage:

`./gencov.py --duts=duts.json`

As a command line argument, a JSON file is expected. It should contain an `array` of DUT properties representing the attributes relevant to the coverage report and attributes of the target DUT.

## Structure of the JSON file

```json
[
    {
        "ip": "<ip address of the target DUT>",
        "board": "<board name of the target DUT>",
        "port": "<port number of  the target DUT>",
        "packages": "<a list of packages from where profraws will be collected>"
    }
    ...
    ...
]

```

Sample:
```json
[
    {
        "ip": "vmdut",
        "board": "betty",
        "port": 9222,
        "packages": [
            "tpm_manager",
            "chaps",
            "attestation",
            "u2fd",
            "bootlockbox",
            "cryptohome",
            "vtpm",
            "trunks",
            "pca_agent"
        ]
    },
    {
        "ip": "localhost",
        "port": 2223,
        "board": "cave",
        "packages": [
            "tpm_manager",
            "chaps",
            "attestation",
            "u2fd",
            "bootlockbox",
            "cryptohome",
            "pca_agent"
        ]
    }
]
```
