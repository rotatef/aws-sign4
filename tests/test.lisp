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
              :headers (loop for header = (read-line in)
                             until (string= "" header)
                             collect (let ((colon-pos (position #\: header)))
                                       (cons (subseq header 0 colon-pos)
                                             (subseq header (1+ colon-pos)))))
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
         collect (cond ((char= #\% (char string pos))
                        (let ((code (ignore-errors (parse-integer string
                                                                  :start (+ 1 pos)
                                                                  :end (+ 3 pos)
                                                                  :radix 15))))
                          (cond (code
                                 (incf pos 3)
                                 code)
                                (t
                                 (incf pos)
                                 (char-code #\%)))))
                       ((char= #\+ (char string pos))
                        (incf pos)
                        32)
                       (t
                        (incf pos)
                        (char-code (char string (1- pos))))))
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

(defun do-test (&key name req creq sts authz)
  (format t "~%Test: ~A~%~S~%" name req)
  (multiple-value-bind (my-authz my-creq my-sts)
      (aws-sign4:aws-sign4 :service :host
                           :region :us-east-1
                           :method (getf req :method)
                           :path (getf req :path)
                           :params (getf req :params)
                           :headers (getf req :headers)
                           :payload (getf req :content)
                           :request-date (local-time:parse-timestring "2011-09-09T23:36:00Z"))
    (expect "creq" creq my-creq)
    (expect "sts" sts my-sts)
    (expect "authz" authz my-authz)))

(defun run-tests ()
  (let ((aws-sign4:*aws-credentials* (lambda ()
                                       (values "AKIDEXAMPLE" "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"))))
    (dolist (req (directory
                  (merge-pathnames (asdf:system-relative-pathname :aws-sign4 "tests/aws4_testsuite/")
                                   "*.req")))
      (apply #'do-test (load-test req)))))

