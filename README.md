Common Lisp library for Amazon Web Services signing version 4.
==============================================================

Project home: https://github.com/copyleft/aws-sign4

This library implements the Signature Version 4 Signing Process, as
described here:
http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

Highlights:

* Passes all tests in the test suite from Amazon.
* Tested on ABCL, ACL, CCL, CLISP and SBCL.
* Signing only, not tied to a specific http client library.

See also example/example.lisp.

Variable
```
AWS-SIGN4:*AWS-CREDENTIALS*
```

Bind this variable to a function returning two values, the access key
and the secret key.

```
AWS-SIGN4:AWS-SIGN4 &key ...
```

Calculates the signature for a http request.

Parameters:

* region - String designator for the AWS region. Default "us-east-1".
* service - String designator for the AWS service name.
* method - String designator for the http method.
* host - The hostname/endpoint to for the request. Default is the
  value of the host header.
* path - The path part of the request URI.
* params - The query parameters of the URI as an assoc list.
* headers - The headers as an assoc list as an assoc list.
* payload - The payload, as a string or vector of octets. Strings are
  encoded to octets using UTF-8.
* date-header - The name of the date-header, `:X-AMZ-DATE` or
  `:DATE`. Default `:X-AMZ-DATE`.
* request-date - The request date as a local-time timestamp.
  Default `(LOCAL-TIME:NOW)`.
* expires - Provides the time period, in seconds, for which the generated presigned URL is valid.
* scheme - Scheme used in presigned URL, defaults to https.

Returns seven values. Only the two first are needed, the others are
useful for debugging.

* If expire is nil or not supplied, the value of `"Authorization"` header.
  If expire is supplied, the presigned URL.
* Value of `"X-Amz-Date"` or `"Date"` header.
* Canonical request
* String to sign
* Credential scope
* Signed headers
* Signature
