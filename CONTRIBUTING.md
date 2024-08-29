# Contribution and Development Guide

## What Wayne OS project looking forward from you
#### Contribution
- Reporting: [hw_compatibility_information.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/release/hw_compatibility_information.md), [known_issues.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/release/known_issues.md)
- Suggestion/Solution: [Issues](https://github.com/wayne-incorporated/wayne-os/issues)
- Coding: bug fix, refactoring, improving error/help messages
- Documentation: update, revision, writing tutorial/manual, link
- Translation: translating English documents to other languages
#### Development to use
- Starting your own OS project: make a branch yourself or fork this project
- Download OS binaries: [Release](https://github.com/wayne-incorporated/wayne-os/releases)

## Directories of repository
Wayne OS project repository doesn't manage upstream Chromium OS source codes as it manages only modified/additional source codes.
<br>Using/Developing Wayne OS project repository requires knowledge/experience about upstream Chromium OS project.
<br>The upstream source codes and build instructions can be referred from [Chromium OS project](http://dev.chromium.org/chromium-os).
- src: Modified/added codes from Chromium OS codes. The directory path is the same with the path of Chromium OS src.
- patches_on_binary: Additional codes that should be added in the OS binary. The directory path is the same with the path of Chromium OS binary.
- docs: Manuals for using and development.

## Branch
#### Managed by maintainer
- *main*: The latest branch.
- *stabilize*: Working branch for release.
- *release*: (most) Stabled and released Wayne OS version.
#### Managed by contributor
- You can make your own branch, source, and docs if you need it.
- Refer the below notation rules.

## Notation guide
#### Date & time
- Content: [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601) format
- File/Dir/Branch: YYMMDD or YYMMDD_HHMM format

#### Naming for file/dir/branch
- Only Latin alphabet's (English) lowercases (ASCII code 97-122), hypen (ASCII code 45), underscore (ASCII code 95), Arabic numerals (ASCII code 48-57) are allowed
<!--- 
Most of files in Chromium OS project are written in lowercases, except the files which are from external project.
If we allow uppercases, sometimes it's confuse (ex: docs? Docs? DOCS?).
--->
- If content of file/dir is written in non-English, the name of file/dir can also be non-English
- For special file/dir that is required to emphasize customarily, the name can be written in uppercases all (ex: README, LICENSE)
- Avoid special characters, except minus/hyphen[-] and underscore[_]
- Relationship between objects/subjects should be expressed by minus/hyphen[-]
- Space should be replaced to underscore[_]
- For history and to distinguish similar names, [YYMMDD]/[YYMMDD_HHMM]/[identification number] can be added

|format|example|
| --- | --- |
|[description]|known_issue.md<br>README.md|
|[description]-[description]|cros-src<br>how-to|
|[subject]-[description]-[date]|report-hw_compatibility-210815|
|[subject]-[description]-[date_time]|report-hw_compatibility-210815_1159|
|[subject]-[reference]-[description]-[identification number]|report-hw_compatibility-r1|

## [Markdown](https://en.wikipedia.org/wiki/Markdown) guide
- Headers:
    - # Title Can Be Written With Capital Letters (This is Optional)
    - ## Header should be start with capital letter
    - #### Small header also similar with above header
    - classify
        - detail classify
- Proper noun or name of version/reference: *write in Italic font* or _write in Italic font_
- Emphasis: **write in bold font** or __write in bold font__
- Emphasizing proper noun of name of version/reference: ***write in bold & Italic font*** or ___write in bold & Italic font___
- Code or commands: `use back-ticks`
    ```
    Or use triple back-ticks/tildes
    ```
- Comment
```
[comment]: # (Your comment will not be shown to public)
<!--- 
But It will help other contributors!
--->
```
