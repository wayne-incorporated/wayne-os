# Contribution and Development Guide

## What Wayne OS project looking forward from you
#### Contribution
- Reporting: [hw_compatibility_information.md](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/release/hw_compatibility_information.md), [known_issues.md](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/release/known_issues.md)
- Suggestion/Solution: [Issues](https://gitlab.com/wayne-inc/wayne_os/-/issues)
- Coding: bug fix, refactoring, improving error/help messages
- Documentation: update, revision, writing tutorial/manual, link
- Translation: translating English documents to other languages
#### Development to use
- Starting your own OS project: make a branch yourself or fork this project
- Download OS binaries: [wayne-os.com](https://wayne-os.com)

## Joining Wayne OS project
1) Join Gitlab: https://gitlab.com/users/sign_in
2) Go to https://gitlab.com/wayne-inc/wayne_os
3) Press _Request Access_ button that is near the project title "Wayne OS", then wait for approval
4) After approval, [Check](https://gitlab.com/wayne-inc/wayne_os/-/project_members) your [role and permission](https://docs.gitlab.com/ee/user/permissions.html)
5) By default, each project member will get *Developer* role

## Directories of repository
Wayne OS project repository doesn't manage upstream Chromium OS source codes as it manages only modified/additional source codes.
<br>Using/Developing Wayne OS project repository requires knowledge/experience about upstream Chromium OS project.
<br>The upstream source codes and build instructions can be referred from [Chromium OS project](http://dev.chromium.org/chromium-os).
- src: modified/added codes from Chromium OS codes. The directory path is the same with the path of Chromium OS source
- patches_on_binary: additional codes that should be added in the OS binary. The directory path is the same with the path of Chromium OS binary
- docs: documents that are referred in [wayne-os.com](https://wayne-os.com). English _document_ in en directory should be made first, then translate to other languages

## Issue
- All project members can see/create [Issues](https://gitlab.com/wayne-inc/wayne_os/-/issues)
- There are Wayne OS development status, plan, direction

## Branch
- *master*: Default, protected, at least *Maintainer* is allowed to push (add/modify/delete files and commit) or merge (allow merge request)
- At least *Developer* is allowed to create branches and push or merge to those
- Avoid confusing branch name that is similar with existing branch name
- You can delete your temporary branch after merge
- If you want to protect certain branch and restrict push/merge authority, request it to the project owner in [Issues](https://gitlab.com/wayne-inc/wayne_os/-/issues)

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