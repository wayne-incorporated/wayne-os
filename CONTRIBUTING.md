# Contribution and Development Guide

## What Wayne OS project is looking forward to from you
#### Contribution
- Reporting: [hw_compatibility_information.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/release/hw_compatibility_information.md), [known_issues.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/release/known_issues.md)
- Suggestion/Solution: [Issues](https://github.com/wayne-incorporated/wayne-os/issues)
- Coding: bug fixing, refactoring, error/help messages improving
- Documentation: update, revision, tutorial/manual writing, link addition
- Translation: Translation of English documents into other languages
#### Development for use
- Start your own OS project: create a branch or fork this project
- Download OS binaries: [Release](https://github.com/wayne-incorporated/wayne-os/releases)

## Directories of repository
Wayne OS project repository doesn't include the upstream Chromium OS source code as it only manages modified/additional source code.
<br>Using/Developing Wayne OS project repository requires knowledge/experience with the upstream Chromium OS project.
<br>The upstream source code and build instructions can be referred from [Chromium OS project](http://dev.chromium.org/chromium-os).
- src: Modified/added code from Chromium OS code. The directory path is the same with the path of Chromium OS src.
- patches_on_binary: Additional code that should be added to the OS binary. The directory path is the same with the path of Chromium OS binary.
- docs: Manuals for usage and development.

## Branch
#### Managed by maintainer
- *main*: The latest branch.
- *stabilize*: The working branch for preparing releases.
- *release*: The (most) Stable branch, containing released versions of Wayne OS.
#### Managed by contributor
- You can create your own branch, source code, and documentation asneeded.
- Refer to the below notation rules.

## Notation guide
#### Date & time
- Content: [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601) format
- File/Dir/Branch: YYMMDD or YYMMDD_HHMM format

#### Naming for file/dir/branch
- Only lowercase Latin alphabet (English) characters (ASCII code 97-122), hyphens (ASCII code 45), underscores (ASCII code 95), and Arabic numerals (ASCII code 48-57) are allowed.
<!--- 
Most of files in Chromium OS project are written in lowercases, except the files which are from external project.
If we allow uppercases, sometimes it's confuse (ex: docs? Docs? DOCS?).
--->
- If the content of file/dir is written in non-English, the name of file/dir may also be non-English
- For special file/dir that is required to emphasize customarily, the name can be written entirely in uppercase (ex: README, LICENSE)
- Avoid special characters, except for minus/hyphen[-] and underscore[_]
- Use hyphens [-] to express relationships between objects or subjects.
- Replace space to underscore[_]
- For historical purposes or to distinguish between similar names, you may add [YYMMDD], [YYMMDD_HHMM], or an identification number.

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
