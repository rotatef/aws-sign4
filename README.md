Common Lisp library for Amazon Web Services signing version 4.
==============================================================

Project home: https://github.com/rotatef/aws-sign4

This library implements the Signature Version 4 Signing Process, as
described here:
http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

## Highlights:

* Passes all tests in the test suite from Amazon.
* Tested on ABCL, ACL, CCL, CLISP and SBCL.
* Signing only, not tied to a specific http client library.

## Example

See [example.lisp](example/example.lisp) for an example of using Drakma to make a request to SWF.

S3 supports [presigned URL](http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html).
This make is possible to give a web browser temporary access to download an object directly from S3. Example:

```lisp
(let ((aws-sign4:*aws-credentials*
        (lambda ()
          (values "AKIAIOSFODNN7EXAMPLE" "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))))
  (aws-sign4:aws-sign4 :region :eu-west-1
                       :service :s3
                       :host "s3-eu-west-1.amazonaws.com"
                       :path "/some-bucket/some-file"
                       :expires 300)) 
=> "https://s3-eu-west-1.amazonaws.com/some-bucket/some-file?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20170908%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20170908T121925Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=42c841837976e9c206f80554b50aa879fdb3aa4f3e6f61934ce8eba436205abf                      
```

## API

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
