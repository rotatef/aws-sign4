;;;;  aws-sign4
;;;;
;;;;  Copyright (C) 2013 Thomas Bakketun <thomas.bakketun@copyleft.no>
;;;;
;;;;  This library is free software: you can redistribute it and/or modify
;;;;  it under the terms of the GNU Lesser General Public License as published
;;;;  by the Free Software Foundation, either version 3 of the License, or
;;;;  (at your option) any later version.
;;;;
;;;;  This library is distributed in the hope that it will be useful,
;;;;  but WITHOUT ANY WARRANTY; without even the implied warranty of
;;;;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;;;  GNU General Public License for more details.
;;;;
;;;;  You should have received a copy of the GNU General Public License
;;;;  along with this library.  If not, see <http://www.gnu.org/licenses/>.

(in-package :aws-sign4)

(defun ensure-octets (data)
  (if (stringp data)
      (flex:string-to-octets data :external-format :utf-8)
      data))

(defun hash (data)
  (ironclad:digest-sequence :sha256 data))

(defun hex-encode (bytes)
  (ironclad:byte-array-to-hex-string bytes))

(defun url-encode (string &key (escape% t))
  "URL-encodes a string using the external format UTF-8. If keyword
parameter ESCAPE% is NIL, the % is not escaped."
  (with-output-to-string (s)
    (loop for c across string
          for index from 0
          do (cond ((or (char<= #\0 c #\9)
                        (char<= #\a c #\z)
                        (char<= #\A c #\Z)
                        ;; note that there's no comma in there - because of cookies
                        (find c "-_.~" :test #'char=))
                    (write-char c s))
                   ((and (not escape%)
                         (char= #\% c))
                    (write-char c s))
                   (t (loop for octet across
                            (ensure-octets (string (char string index)))
                            do (format s "~:@(%~2,'0X~)" octet)))))))

(defun create-canonical-path (path)
  (let ((input (split-sequence:split-sequence #\/ path))
        (output nil))
    (loop while input do
          (cond ((or (string= (car input) "")
                     (string= (car input) "."))
                 (unless (cdr input)
                   (push "" output)))
                ((string= (car input) "..")
                 (pop output))
                (t
                 (push (car input) output)))
          (pop input))
    (format nil "/~{~A~^/~}"
            (mapcar (lambda (x)
                      (url-encode x :escape% nil))
                    (reverse output)))))

(defun create-canonical-query-string (params)
  (format nil "~{~A~^&~}"
          (sort (loop for (key . value) in params
                      collect (format nil "~A=~A"
                                      (url-encode (string key))
                                      (url-encode (princ-to-string value))))
                #'string<)))

(defun trimall (string)
  (cl-ppcre:regex-replace-all "^\\s+|(?<=\\s)\\s+|\\s+$" string ""))

(defun merge-duplicate-headers (headers)
  (loop for header = (pop headers)
        while header
        collect `(,(car header)
                  ,@(cons (cdr header)
                          (loop while (equal (car header) (caar headers))
                                collect (cdr (pop headers)))))))

(defun create-canonical-headers (headers)
  (merge-duplicate-headers
   (sort (loop for (key . value) in headers
               collect (cons (string-downcase key) (trimall value)))
         #'string<
         :key #'car)))

(defun create-signed-headers (canonical-headers)
  (format nil "~{~A~^;~}" (mapcar #'car canonical-headers)))

(defun create-canonical-request (method canonical-path canonical-query-string canonical-headers signed-headers payload)
  (with-output-to-string (str)
    ;; HTTPRequestMethod:
    (write-line (string-upcase method) str)
    ;; CanonicalURI:
    (write-line canonical-path str)
    ;; CanonicalQueryString:
    (write-line canonical-query-string str)
    ;; CanonicalHeaders:
    (dolist (header canonical-headers)
      (format str "~A:~{~A~^,~}~%" (car header) (cdr header)))
    (write-line "" str)
    ;; SignedHeaders
    (write-line signed-headers str)
    ;; Payload
    (if payload
        (write-string (hex-encode (hash (ensure-octets payload))) str)
        (write-string "UNSIGNED-PAYLOAD" str))))

(defun string-to-sign (request-date credential-scope canonical-request)
  (with-output-to-string (str)
    (write-line "AWS4-HMAC-SHA256" str)
    (write-line request-date str)
    (write-line credential-scope str)
    (write-string (hex-encode (hash (ensure-octets canonical-request))) str)))

(defun hmac (key data)
  (let ((hmac (ironclad:make-hmac (ensure-octets key) :sha256)))
    (ironclad:update-hmac hmac (ensure-octets data))
    (ironclad:hmac-digest hmac)))

(defun calculate-signature (k-secret string-to-sign date region service)
  (let* ((k-date (hmac (concatenate 'string "AWS4" (secret-values:ensure-value-revealed k-secret)) date))
         (k-region (hmac k-date region))
         (k-service (hmac k-region service))
         (k-signing (hmac k-service "aws4_request")))
    (hex-encode (hmac k-signing string-to-sign))))

(defvar *aws-credentials* nil)

(defun get-credentials ()
  (unless (functionp *aws-credentials*)
    (error "Please bind *AWS-CREDENTIALS* to a function."))
  (funcall *aws-credentials*))

(defun aws-sign4 (&key
                    (region :us-east-1)
                    service
                    (method :get)
                    host
                    path
                    params
                    headers
                    payload
                    (date-header  "X-Amz-Date")
                    (request-date (local-time:now))
                    expires
                    (scheme :https))
  (check-type service (and (not null) (or symbol string)) "an AWS service designator")
  (check-type path string)
  (multiple-value-bind (access-key private-key)
      (get-credentials)
    (labels ((get-header (key)
               (cdr (assoc key headers :test #'string-equal))))
      (let* ((host (or host (get-header :host)))
             (x-amz-date (local-time:format-timestring nil
                                                       request-date
                                                       :format '((:year 4) (:month 2) (:day 2) #\T
                                                                 (:hour 2) (:min 2) (:sec 2)
                                                                 :gmt-offset-or-z)
                                                       :timezone local-time:+utc-zone+))
             (scope-date (subseq x-amz-date 0 8))
             (region (string-downcase region))
             (service (etypecase service
                        (symbol (string-downcase service))
                        (string service)))
             (credential-scope (format nil "~A/~A/~A/aws4_request" scope-date region service)))
        (unless host
          (error "Error in arguments to aws-sign4. Missing host."))
        (unless (get-header :host)
          (push (cons :host host) headers))
        (unless expires
          (pushnew (cons date-header x-amz-date) headers :key #'car :test #'string-equal))
        (let* ((canonical-headers (create-canonical-headers headers))
               (signed-headers (create-signed-headers canonical-headers)))
            (when expires
              (push (cons "X-Amz-Algorithm" "AWS4-HMAC-SHA256") params)
              (push (cons "X-Amz-Credential" (format nil "~A/~A"
                                                     (secret-values:ensure-value-revealed access-key)
                                                     credential-scope))
                    params)
              (push (cons "X-Amz-Date" x-amz-date) params)
              (push (cons "X-Amz-Expires" (princ-to-string expires)) params)
              (push (cons "X-Amz-SignedHeaders" signed-headers) params))
          (let* ((canonical-path (create-canonical-path path))
                 (canonical-query-string (create-canonical-query-string params))
                 (creq (create-canonical-request method canonical-path canonical-query-string canonical-headers signed-headers payload))
                 (sts (string-to-sign x-amz-date
                                      credential-scope
                                      creq))
                 (signature (calculate-signature private-key
                                                 sts
                                                 scope-date
                                                 region
                                                 service)))
            (values
             (if expires
                 (format nil "~A://~A~A?~A&X-Amz-Signature=~A"
                         (string-downcase scheme)
                         host
                         canonical-path
                         canonical-query-string
                         signature)
                 (format nil
                         "AWS4-HMAC-SHA256 Credential=~A/~A, SignedHeaders=~A, Signature=~A"
                         (secret-values:ensure-value-revealed access-key)
                         credential-scope
                         signed-headers
                         signature))
             x-amz-date
             creq
             sts
             credential-scope
             signed-headers
             signature)))))))
