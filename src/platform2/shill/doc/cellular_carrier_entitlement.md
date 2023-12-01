# Cellular Carrier Entitlement
*Updated April 2023*

The [CarrierEntitlement] class implements the carrier entitlement check
functionality in shill. It is responsible for connecting to a remote server and
checking if a user is allowed to use the cellular connection for
tethering/hotspot on carriers that require this verification.

The following steps are performed by the CarrierEntitlement class when checking
carrier entitlement:
*  The class constructs a POST/GET request based on the values of
`mhs_entitlement_*` in the [modb].
*  For a POST request, parameters such as the IMSI will be added to the request
body if any `mhs_entitlement_param` is configured in the modb. For a GET
request, no parameters are added.
*  The class opens a connection to the URL.
*  The class sends a request to the server.
*  The class reads the response from the server.
*  The class parses the response and determines if the user is allowed to use
the cellular connection for tethering/hotspot.

## Server behavior

The server should preferably accept POST requests only, as the POST request
allows for a message body with parameters. The server should expect a request
of the type 'application/json'.

By default, the request will not contain any fields, unless the [modb] contains
a `mhs_entitlement_param` with the required field by the server. An example of
this field could be the IMSI or IMEI.

If the entitlement check is OK, the server shall respond with a message
HTTP/1.1 200 OK.

If the entitlement check is NOK. the server shall respond with HTTP/1.1 403
Forbidden, with an error code in the body. The error code is optional. The
following are recognized error codes:

*  1000 - User does not subscribe to tethering
*  1001 - Syntax error of HTTP Request
*  1002 - FUTURE USE
*  1003 - Carrier does not recognize user
*  5000 - Server error: When the server returns this error, the device will use
the previous cached value if there is any.

Examples of commands to validate the server API:
```
# Without any parameters
curl ${SERVER_URL} --request POST --data-raw '{}' --header 'Content-Type:application/json'

# With IMSI parameter
curl ${SERVER_URL} --request POST --data-raw '{"imsi": "001010000000005"}' --header 'Content-Type:application/json'
```

[modb]: ../mobile_operator_db/serviceproviders.textproto
[CarrierEntitlement]: ../cellular/carrier_entitlement.h
