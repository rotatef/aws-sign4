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
  (labels ((helper (rest)
             (cond 
               ((null rest) nil)
               ((string= (car rest) "..")
                (helper (cdr (helper (cdr rest)))))
               ((string= (car rest) ".")
                (helper (cdr rest)))
               (t (cons (car rest)
                        (helper (cdr rest)))))))
    (let* ((splitted
            (loop for x on 
                 (cdr
                  (split-sequence:split-sequence #\/ path))
               unless (and (string= (car x) "")
                           (cdr x))
               collect (car x)))
          (res (reverse 
                (helper
                 (reverse splitted)))))
      (format nil "/~{~A~^/~}" 
               (mapcar (lambda (x)
                         (url-encode 
                          x
                          :external-format :latin-1
                          :escape nil))
                       res)))))
(defun merge-duplicates* (list)
  (when list
    (let* ((rest (merge-duplicates (cdr list)))
           (nextkey (caar rest))
           (nextval (cdar rest))
           (key (caar list))
           (val (cdar list)))
      (if (equalp nextkey key)
          (cons 
           (progn
             (cons key 
                   (append nextval val)))
           (cdr rest))
          (cons (cons key val)
                rest)))))


(defun merge-duplicates (list)
  (reverse (merge-duplicates* (reverse list))))




(defun create-canonical-request (request-method path params headers payload)
  (labels ((getkey (v &optional (car nil))
             (when car
               (setf v (car v)))
             (when (symbolp v)
               (setf v (symbol-name v)))
             (string-downcase v))
           (signed-headers (str &optional (newline t))
             (prog1
                 (format str "~{~A~^;~}" 
                         (remove-duplicates (sort (copy-list (loop for x in headers
                                                                collect (getkey x t)))
                                                  #'string<)
                                            :test #'equalp))
               (when newline
                 (write-line "" str)))
             ))
    (values
     (with-output-to-string (str)
       (format str "~A~%" (ecase request-method 
                            (:get "GET") 
                            (:post "POST")))
       (format str "~A~%" (create-canonical-path path))
       (loop for  x on (sort (copy-list params) #'string< :key (lambda (x) 
                                                                 (format nil "~S~S"
                                                                         (getkey x t)
                                                                         (cdr x)
                                                                         )))
          for (key value) = (car x)
          do (format str "~A=~A~A" 
                     (url-encode key)
                     (url-encode value)
                     (if (cdr x)
                         "&" "")))
       (format str "~%")
       (loop for  x on (merge-duplicates (sort (copy-list headers) #'string< :key (lambda (x) (getkey x t))))
          for (key . value) = (car x)
          do (format str "~A:~{~A~^,~}~%" 
                     (hunchentoot:url-encode (getkey key))
                     (loop for x in (sort (copy-list value) #'string<)
                        collect (string-trim " " x))
                     ))
       (write-line "" str)
       (signed-headers str)
       (write-string (hex-encode (hash payload)) str))
     (signed-headers nil nil)
     )))

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

(defun authorization-header (access-key key credential-scope date region service request-method path params headers payload)
  (multiple-value-bind (creq singed-headers)
      (create-canonical-request request-method path params headers payload)
    (let* ((sts (string-to-sign (cadr (assoc "X-Amz-Date" headers :test #'equalp))
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
            (format nil "~A/~A/~A/aws4_request" date region service)
            date
            region
            service
            :post
            path
            nil
            (append `(( "host" ,endpoint)
                      ("Content-Type" ,content-type))
                    (loop for x in additional-headers
                          collect (list (car x) (cdr x))))
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
