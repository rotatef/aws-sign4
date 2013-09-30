(in-package :aws-sign4)

(defun ensure-octets (data)
  (if (stringp data)
      (flex:string-to-octets data :external-format :utf-8)
      data))

(defun hash (data)
  (ironclad:digest-sequence :sha256 data))

(defun hex-encode (bytes)
  (ironclad:byte-array-to-hex-string bytes))

(defun url-encode (string &key (escape t))
  "URL-encodes a string using the external UTF-8."
  (with-output-to-string (s)
    (loop for c across string
          for index from 0
          do (cond ((or (char<= #\0 c #\9)
                        (char<= #\a c #\z)
                        (char<= #\A c #\Z)
                        ;; note that there's no comma in there - because of cookies
                        (find c "-_.~" :test #'char=))
                    (write-char c s))
                   ((and (not escape)
                         (char= #\% c))
                    (write-char c s))
                   (t (loop for octet across
                            (ensure-octets (string (char string index)))
                            do (format s "%~2,'0x" octet)))))))

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
                      (url-encode x :escape nil))
                    (reverse output)))))

(defun create-canonical-query-string (params)
  (format nil "~{~A~^&~}"
          (sort (loop for (key . value) in params
                      collect (format nil "~A=~A" (url-encode (string key)) (url-encode value)))
                #'string<)))

(defun trimall (string)
  (string-trim '(#\Space #\Tab) string))

(defun merge-duplicate-headers (headers)
  (loop for header = (pop headers)
        while header
        collect `(,(car header)
                  ,@(sort (cons (cdr header)
                                (loop while (equal (car header) (caar headers))
                                      collect (cdr (pop headers))))
                          #'string<))))

(defun create-canonical-headers (headers)
  (merge-duplicate-headers
   (sort (loop for (key . value) in headers
               collect (cons (string-downcase key) (trimall value)))
         #'string<
         :key #'car)))


(defun create-canonical-request (method path params headers payload)
  (let* ((canonical-headers (create-canonical-headers headers))
         (signed-headers (format nil "~{~A~^;~}" (mapcar #'car canonical-headers))))
    (values (with-output-to-string (str)
              ;; HTTPRequestMethod:
              (write-line (string-upcase method) str)
              ;; CanonicalURI:
              (write-line (create-canonical-path path) str)
              ;; CanonicalQueryString:
              (write-line (create-canonical-query-string params) str)
              ;; CanonicalHeaders:
              (dolist (header canonical-headers)
                (format str "~A:~{~A~^,~}~%" (car header) (cdr header)))
              (write-line "" str)
              ;; SignedHeaders
              (write-line signed-headers str)
              ;; Payload
              (write-string (hex-encode (hash (ensure-octets payload))) str))
            signed-headers)))

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
  (let* ((k-date (hmac (concatenate 'string "AWS4" k-secret) date))
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
                    method
                    host
                    path
                    params
                    (request-date (local-time:now) request-date-p)
                    headers
                    payload)
  (multiple-value-bind (access-key private-key)
      (get-credentials)
    (let* ((x-amz-date (local-time:format-timestring nil
                                                     request-date
                                                     :format '((:year 4) (:month 2) (:day 2) #\T
                                                               (:hour 2) (:min 2) (:sec 2)
                                                               :gmt-offset-or-z)
                                                     :timezone local-time:+utc-zone+))
           (scope-date (subseq x-amz-date 0 8))
           (region (string-downcase region))
           (service (string-downcase service))
           (credential-scope (format nil "~A/~A/~A/aws4_request" scope-date region service)))
      (unless (assoc "host" headers :test #'string-equal)
        (push (cons :host host) headers))
      (unless request-date-p
        (push (cons :x-amz-date x-amz-date) headers))
      (multiple-value-bind (creq singed-headers)
          (create-canonical-request method path params headers payload)
        (let* ((sts (string-to-sign x-amz-date
                                    credential-scope
                                    creq))
               (signature (calculate-signature private-key
                                               sts
                                               scope-date
                                               region
                                               service)))
          (values
           (format nil
                   "AWS4-HMAC-SHA256 Credential=~A/~A, SignedHeaders=~A, Signature=~A"
                   access-key
                   credential-scope
                   singed-headers
                   signature)
           x-amz-date
           creq
           sts
           credential-scope
           singed-headers
           signature))))))
