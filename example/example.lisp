(in-package :aws-sign4-example)

(defun swf-request (region action payload)
  (let ((host (format nil "swf.~(~A~).amazonaws.com" region)))
    (multiple-value-bind (authz date)
        (aws-sign4 :region region
                   :service :swf
                   :method :post
                   :host host
                   :path "/"
                   :headers `((:x-amz-target . ,(format nil "SimpleWorkflowService.~A" action))
                              (:content-type .  "application/x-amz-json-1.0"))
                   :payload payload)
      (flex:octets-to-string
       (http-request (format nil "https://~A/" host)
                     :method :post
                     :additional-headers `((:x-amz-target . ,(format nil "SimpleWorkflowService.~A" action))
                                           (:x-amz-date . ,date)
                                           (:authorization . ,authz))
                     :content-type "application/x-amz-json-1.0"
                     :content payload
                     :force-binary t)))))

(defun credentials-from-file ()
  (let (access-key secret)
    (with-open-file (in (merge-pathnames ".aws" (user-homedir-pathname)))
      (setf access-key (read-line in))
      (setf secret (read-line in)))
    (lambda ()
      (values access-key secret))))

(defmacro with-aws-credentials (&body body)
  `(let ((*aws-credentials* (credentials-from-file)))
     ,@body))

(defun test ()
  (with-aws-credentials
    (swf-request :eu-west-1 "ListDomains" "{\"registrationStatus\":\"REGISTERED\"}")))
