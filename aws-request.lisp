(defun ensure-octets (data)
  (if (stringp data)
      (sb-ext:string-to-octets data :external-format :utf-8)
      data))

(defun hash (data)
  (ironclad:digest-sequence :sha256
                            (sb-ext:string-to-octets data
                                                     :external-format :utf-8)))
(defun hex-encode (bytes)
  (ironclad:byte-array-to-hex-string bytes))


(defvar *credentials* nil)

(defun file-credentials (file)
  (with-open-file (str file)
    (list (read-line str) (read-line str))))

(defun initialize (credentials)
  (setf *credentials* credentials))

(defun url-encode (string &key (external-format :utf-8)
                               (escape t))
  "URL-encodes a string using the external format EXTERNAL-FORMAT."
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
                           (string-to-octets string
                                             :start index
                                             :end (1+ index)
                                             :external-format external-format)
                         do (format s "%~2,'0x" octet)))))))

(defun create-canonical-path (path)
  (labels ((remove-dots (path)
             (cond ((null path) nil)
               ((string= (car path) "..")
                (cdr (remove-dots (cdr path))))
               ((string= (car path) ".")
                (remove-dots (cdr path)))
               (t (cons (car path)
                        (remove-dots (cdr path)))))))
    (format nil "/~{~A~^/~}"
            (mapcar (lambda (x)
                      (url-encode x :escape nil))
                    (reverse
                     (remove-dots
                      (reverse (split-sequence:split-sequence #\/ path :remove-empty-subseqs t))))))))

(defun create-canonical-query-string (params)
  (with-output-to-string (str)
    (labels ((getkey (v &optional (car nil))
               (when car
                 (setf v (car v)))
               (when (symbolp v)
                 (setf v (symbol-name v)))
               (string-downcase v)))
      (loop for x on (sort (copy-list params) #'string< :key (lambda (x)
                                                               (format nil "~S~S"
                                                                       (getkey x t)
                                                                       (cdr x)
                                                                       )))
            for (key value) = (car x)
            do (format str "~A=~A~A"
                       (url-encode key)
                       (url-encode value)
                       (if (cdr x)
                           "&" ""))))))






(defun trimall (string)
  (string-trim '(#\Space #\Tab) string))

(defun merge-duplicate-headers (headers)
  (loop for header = (pop headers)
        while header
        collect `(,(car header)
                   ,(cdr header)
                   ,@(loop while (equal (car header) (caar headers))
                           collect (cdr (pop headers))))))

(defun create-canonical-headers (headers)
  (merge-duplicate-headers
   (stable-sort (loop for (key . value) in headers
                      collect (cons (string-downcase key) (trimall value)))
                #'string<
                :key #'car)))


(defun create-canonical-request (request-method path params headers payload)
  (let* ((canonical-headers (create-canonical-headers headers))
         (signed-headers (format nil "~{~A~^;~}" (mapcar #'car canonical-headers))))
    (values (with-output-to-string (str)
              ;; HTTPRequestMethod:
              (write-line request-method str)
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
              (write-string (hex-encode (hash payload)) str))
            signed-headers)))

(defun string-to-sign (request-date credential-scope canonical-request)
  (with-output-to-string (str)
    (write-line "AWS4-HMAC-SHA256" str)
    (write-line request-date str)
    (write-line credential-scope str)
    (write-string (hex-encode (hash canonical-request)) str)))

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

(defun authorization-header (access-key key x-amz-date date region service request-method path params headers payload)
  (multiple-value-bind (creq singed-headers)
      (create-canonical-request request-method path params headers payload)
    (let* ((credential-scope (format nil "~A/~A/~A/aws4_request" date region service))
           (sts (string-to-sign x-amz-date
                                credential-scope
                                creq))
           (signature
            (calculate-signature
             key
             sts
             date
             region
             service)))
      (values
       (format nil
               "AWS4-HMAC-SHA256 Credential=~A/~A, SignedHeaders=~A, Signature=~A"
               access-key
               credential-scope
               singed-headers
               signature)
       creq
       sts))))

(defun x-amz-date ()
  (local-time:format-timestring nil
                                (local-time:now)
                                :format '((:year 4) (:month 2) (:day 2) #\T
                                          (:hour 2) (:min 2) (:sec 2)
                                          :gmt-offset-or-z)
                                :timezone local-time:+utc-zone+))

(defun aws-request2 (region service endpoint path x-amz-target content-type payload)
  (let* ((x-amz-date (x-amz-date))
         (date (subseq x-amz-date 0 8))
         (region (string-downcase region))
         (service (string-downcase service))
         (additional-headers `(("x-amz-target" . ,x-amz-target)
                               ("x-amz-date" . ,x-amz-date))))
    (unless *credentials*
      (error "AWS credentials missing"))
    (let ((authorization-header
           (authorization-header
            (car *credentials*)
            (cadr *credentials*)
            x-amz-date
            date
            region
            service
            "POST"
            path
            nil
            `((:host . ,endpoint)
              (:content-type . ,content-type)
              ,@additional-headers)
            payload)))
      (push
       (cons "Authorization"
             authorization-header)
       additional-headers)
      (multiple-value-bind (body status-code)
          (drakma:http-request
           (format nil "http://~A~A" endpoint path)
           :method :post
           :additional-headers additional-headers
           :content payload
           :content-type content-type)
        (values
         (when body
           (sb-ext:octets-to-string
            body))
         status-code)))))


(initialize (file-credentials "~/.aws"))

;(aws-request2 :eu-west-1 :swf "swf.eu-west-1.amazonaws.com" "/" "SimpleWorkflowService.ListDomains" "application/x-amz-json-1.0" "{\"registrationStatus\":\"REGISTERED\"}")
