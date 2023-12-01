# DNS

This directory contains DNS library which is a modified copy of Chromium's DNS
code (net/dns). The current files are taken from milestone M88 of the code
with the latest commit hash of `ad67ec1efbf21306b583c4daf34cf2ba4c591237`.

DNS library is used by:
*   Patchpanel's multicast forwarder.
*   DNS proxy for DNS over HTTPS.

It provides DNS functionalities of:
*   Parsing DNS queries.
*   Create raw DNS responses from DNS queries' answers.

## Modifications

The code here is a modification of Chromium's DNS code. The modification is
done to minimize the code imported. Currently, the necessary functions we
want are:
*   `DnsQuery::Parse` (for parsing queries),
*   `DnsResponse::WriteHeader`, `WriteAnswer`, ... (for writing raw responses).

The modification process is done by importing only the necessary functions,
followed by importing the minimal amount of code necessary to make the
necessary functions work. For example, functionality of writing DNS queries
and parsing DNS responses are removed.

Below are the changes made:
*   Namespaces are changed from net to patchpanel.
*   All the necessary files are flattened into one directory.
*   Update `NET_EXPORT` with `BRILLO_EXPORT`.
*   Remove all unneeded functionality.

## Alternatives Considered

An alternative is to having a modified copy of the Chromium's DNS code is to
port the DNS code to libchrome. Although it avoids having to copy and maintain
duplicated code, it has the downsides of needing to continuously update the code
alongside *libchrome* uprevs and having to include the whole DNS code.

Another option would be to use a low level library like *libbind9*. One
disadvantage of going with this approach is introducing additional payload
by adding the development package. The API of the library is also fairly
complicated and prone to introducing semantic bugs.
