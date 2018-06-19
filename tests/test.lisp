(in-package :aws-sign4-tests)

(defun file-content (filename)
  (with-open-file (bin filename :element-type 'flex:octet)
    (with-open-stream (in (flex:make-flexi-stream bin :external-format '(:utf-8 :eol-style :crlf)))
      (with-output-to-string (out)
        (loop
         (multiple-value-bind (line nl) (read-line in nil)
           (unless line
             (return))
           (write-string line out)
           (unless nl
             (write-char #\Newline out))))))))


(defun load-request (filename)
  (with-open-file (bin filename :element-type 'flex:octet)
    (with-open-stream (in (flex:make-flexi-stream bin :external-format '(:utf-8 :eol-style :crlf)))
      (let* ((req-line (read-line in))
             (method-end (position #\Space req-line))
             (uri-start (1+ method-end))
             (uri-end (position #\Space req-line :start uri-start))
             (q-pos (position #\? req-line :start uri-start))
             (path-end (or q-pos uri-end))
             (query-start (when q-pos (1+ q-pos))))
        (list :method (intern (subseq req-line 0 method-end) :keyword)
              :path (subseq req-line uri-start path-end)
              :params (when query-start (query-decode (subseq req-line query-start uri-end)))
              :headers (loop with name
                             for header = (read-line in nil)
                             while header
                             until (string= "" header)
                             collect (if (member (char header 0) '(#\Space #\Tab))
                                         (cons name header)
                                         (let ((colon-pos (position #\: header)))
                                           (cons (setf name (subseq header 0 colon-pos))
                                                 (subseq header (1+ colon-pos))))))
              :content (let* ((content-length (- (file-length bin)
                                                 (file-position bin)))
                              (content (make-array content-length :element-type 'flex:octet)))
                         (read-sequence content bin)
                         content))))))

(defun load-test (filename)
  (list :name (pathname-name filename)
        :req (load-request filename)
        :creq (file-content (make-pathname :type "creq" :defaults filename))
        :sts (file-content (make-pathname :type "sts" :defaults filename))
        :authz (file-content (make-pathname :type "authz" :defaults filename))))

(defun uri-decode (string)
  (flex:octets-to-string
   (loop with pos = 0
         while (< pos (length string))
         append (cond ((and (char= #\% (char string pos))
                            (< pos (- (length string) 2)))
                       (let ((code (parse-integer string
                                                  :start (+ 1 pos)
                                                  :end (+ 3 pos)
                                                  :radix 16)))
                         (cond (code
                                (incf pos 3)
                                (list code))
                               (t
                                (incf pos)
                                (list (char-code #\%))))))
                      ((char= #\+ (char string pos))
                       (incf pos)
                       (list 32))
                      (t
                       (incf pos)
                       (coerce (flex:string-to-octets string :start (1- pos)
                                                             :end pos
                                                             :external-format :utf-8)
                               'list))))
   :external-format :utf-8))

(defun query-decode (string)
  (loop for kv in (split-sequence:split-sequence #\& string)
        for key-end = (position #\= kv)
        collect (if key-end
                    (cons (uri-decode (subseq kv 0 key-end))
                          (uri-decode (subseq kv (1+ key-end))))
                    (cons (uri-decode kv) ""))))

(defun expect (what expect got)
  (unless (string= expect got)
    (format t "Expected ~A:~%~S~%~%Got:~%~S~%" what expect got)
    (break)))

(defun test-presigning ()
  (let ((aws-sign4:*aws-credentials* (lambda ()
                                       (values "AKIAIOSFODNN7EXAMPLE"
                                               "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))))

    (expect "presigned url"
            "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            (aws-sign4:aws-sign4 :region :us-east-1
                                 :service :s3
                                 :method :get
                                 :host "examplebucket.s3.amazonaws.com"
                                 :path "test.txt"
                                 :request-date (local-time:parse-timestring "2013-05-24T00:00:00Z")
                                 :expires 86400))))

(defun do-test (&key name req creq sts authz)
  (format t "~%Test: ~A~%~S~%" name req)
  (multiple-value-bind (my-authz my-date my-creq my-sts)
      (aws-sign4:aws-sign4 :service :service
                           :region :us-east-1
                           :method (getf req :method)
                           :path (getf req :path)
                           :params (getf req :params)
                           :headers (getf req :headers)
                           :request-date (local-time:parse-timestring "2015-08-30T12:36:00Z")
                           :payload (getf req :content))
    (declare (ignore my-date))
    (expect "creq" creq my-creq)
    (expect "sts" sts my-sts)
    (expect "authz" authz my-authz)))

(defun run-tests ()
  (let ((aws-sign4:*aws-credentials* (lambda ()
                                       (values "AKIDEXAMPLE" "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"))))
    (test-presigning)
    (dolist (req (directory
                  (make-pathname :directory (append
                                             (pathname-directory
                                              (asdf:system-relative-pathname
                                               :aws-sign4 "tests/aws-sig-v4-test-suite/aws-sig-v4-test-suite/"))
                                             '(:wild))
                                 :name :wild
                                 :type "req")))
      (apply #'do-test (load-test req)))))

