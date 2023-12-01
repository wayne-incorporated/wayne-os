# Chrome OS Ml Service: How to setup a Chrome Component with your ML model

<div style="color:#f05000;">
NOTE: This document is intended for Google internal consumption. The tools and
steps mentioned here are available to Googlers only.
</div>

This page explains how to setup a Chrome Component that contains your ML model,
so that it becomes available for download and consequently it can be used by ML
Service.

This document is useful for teams who own a feature in ChromeOS that uses ML
Service.

[TOC]

## Prerequisites

You need to have:

1. A trained TFLite model.
2. Any preprocessing or postprocessing file needed by ML Service for your
   feature.
3. Access and permission for a remote storage solution: GS, Bigstore, x20, etc.

The above steps are **not** covered in this document. For more instructions
read: [go/ml-abc](http://go/ml-abc)

## Omaha

Omaha is the server that holds the Chrome Components and handles the creating
and release of them. Omaha provides a UI to manage the component and its
release.

Using Omaha is a required step in this process.

## What you can expect

This process can be summarised as:
1. One CL to create the key material
2. One CL to add the component to Omaha Server
3. Some manual steps in the Omaha Server UI

## Request access to Omaha

You need a team mdb group that includes the people that can access Omaha, which
is the server that hosts all Chrome Components and allows configuration and
release of Components. Your mdb group will get access only to the components
that you own in Omaha. You can't use single users, so either create a new mdb
group for that or use an existing one that works. Avoid adding extra people to
this group as all members of this group will have the permission to completely
mess up the Component and therefore the feature in a matter of a few clicks.

Once you have the mdb group, write to omaha-support@ and request access, along
with the appropriate introdution of your team and feature to them.

## Upload files to a remote storage

Whatever remote storage solution you choose, it must be versioned.

We strongly recommend you use the following conventions. The rest of this page
assumes that and if you change it you'll have to make appropriate changes.

*   Use path: `/<some_path>/<feature_name>/VERSION/files.zip`
*   For VERSION use `YYYYMMDD.v`. For example `20200218.3`, if using
    `YYYY.MM.DD.v` like `2020.02.18.3`, Omaha will canonicalize it to
    `2020.2.18.3`.
*   Put all files inside a zip file and name it `files.zip`

## Add a new Component

This step adds a new Component to the Omaha server.

Follow instructions in [this documentation][add-component-doc]. In particular,
pay attention to the following.

1. As `key_name` follow convention: `ml_service_<feature_name>_crx[private/public]`
2. When you create a CRX key, **make sure you save the public key** that you'll
   find inside the file `~/keystore_public_key_prod.der`! If you don't, you'll
   have to repeat the step or the component won't be usable.
3. When you write the CL that adds the components, given that all files are in a
   zip archive, use `FileProviderComponent.ArchiveType.ARCHIVE_FILE` as the last
   argument of `FileProviderComponent`.
   Do not create your custom `FileProvider`.
4. To get the CRX ID of the Component, use command:
   `openssl dgst -sha256 path/to/keystore_public_key_prod.der | sed -e "s/.* //" | head -c 32 | tr 0-9a-f a-p; echo`

For reference, see this example CL: [cl/282662189](http://cl/282662189).

### Upload a new version to an existing Component

To upload a new version, you just need to upload the new files to
`/<some_path>/<feature_name>/NEW_VERSION/files.zip`, see [Upload files to a
remote storage], Omaha will create a new version automatically.

## Check that the Component is setup correctly

Generating the key material takes up to two weeks to propagate.

Once all the above steps are done, navigate to http://omahaconsole/ and you
should see your component listed there. Each version column should have an ID or
CL number for your component. You can click on the component name to open a page
with information about the component and the various versions, but there's
nothing for you to do here.

Navigate to http://omaharelease/. You should see your componnent listed there.
Click on the component name and check that you have at least one entry under
"Active File Groups".

## Use Omaha to manage the release of the Component

On http://omaharelease/ you can fully manage the release of your component.
Here's an explanation of the various sections of the UI.

### File Groups
File Groups are automatically created. Every single file that has been imported
and not cleaned up is listed under "**Inactive File Groups**".
"**Active File Groups**" contains the subset that is currently pushed to some cohort.

### Options
Options allows to push to live or staging. As long as we are in staging we are
safe, nothing will happen to production.

At the beginning it's set to staging. A team should perform the initial
experimentation and checks on the component. Once the component is ready to be
served to end-users, switch to live.

### Automation
The "File Importer" needs to be the one specific to your feature. You can find it
in the list. Never change it.

"Push Scheduler" determines how the component is pushed. Here you basically have
only two options you are going to use: NONE or LATEST_TO_AUTO. The former
disables automatic push, so every file/version that you upload needs to be
pushed manually or no new version will be pushed. The latter automatically
pushes the latest version to the Cohort called "Auto".
**We recommend NONE**, so that you don't accidentally push the latest model to the
largest group of population.

"Cleanup" is optional. It simply cleans up old inactive versions.
**We recommend** to disable it.

"Committer": leave on "Omaha", never change it.

### Access Control
Ignore.

### Minimum System Requirements
Ignore.

### Cohorts
A Cohort is a subset of the population.

**Cohorts Manage**
In this section you can create groups and sub groups. "matches" is followed by
a Regex.
The list of attributes that can be used for the cohort definition is documented
in the [Omaha server protocol][omaha-protocol].
Note: If a client comes up in more than one cohort, only the highest cohort in
the list will be applied to it. So be careful. The widest cohort needs to go
at the bottom.

## FAQs

Q. How many components can I create on Omaha?

A. 10s is okay, 100 is not. In general, one component per ML feature is enough.
Version experiments and rollouts are controlled by the version number, so a
team can control which specific version of the component a given ChromeOS
device requests. See [this documentation][version-control-oob].


[add-component-doc]: https://g3doc.corp.google.com/company/teams/chrome/component_updater.md#adding-new-components
[omaha-protocol]: https://github.com/google/omaha/blob/HEAD/doc/ServerProtocolV3.md
[version-control-oob]: https://docs.google.com/document/d/11erwhc0Ppul4SPXE7DtvW9wz-0CQmKK4b9dFTloByos
[Upload files to a remote storage]: #Upload-files-to-a-remote-storage
