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
             (uri-end (position #\Space req-line :start uri-start)))
        (list :method (intern (subseq req-line 0 method-end) :keyword)
              :uri (subseq req-line uri-start uri-end)
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

(defun do-test (&key name req creq sts authz)
  (format t "~%Test: ~A~%~S~%" name req)
  (multiple-value-bind (my-headers my-creq my-sts)
      (aws-auth :us-east-1
                :host
                (getf req :method)
                "host.foo.com"
                (getf req :uri)
                nil ; todo query params
                (getf req :headers)
                (getf req :content)
                :date (local-time:parse-timestring "2011-09-09T23:36:00Z")
                :have-x-amz-date nil)
    (unless (string= creq my-creq)
      (format t "Expected creq:~%~S~%~%Got:~%~S~%" creq my-creq)
      (break))
    (unless (string= sts my-sts)
      (format t "Expected sts:~%~A~%~%Got:~%~A~%" sts my-sts)
      (break))))

(defun test ()
  (dolist (req (directory "/home/thomasb/work/scratch/aws4-sign/aws4_testsuite/*.req"))
    (apply #'do-test (load-test req))))

