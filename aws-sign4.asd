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

(defsystem #:aws-sign4
  :name "aws-sign4"
  :licence "GNU General Public Licence 3.0"
  :depends-on (:local-time
               :ironclad
               :split-sequence
               :flexi-streams
               :drakma)
  :serial t
  :components ((:file "package")
               (:file "aws-sign4")))

(defsystem #:aws-sign4-tests
  :name "aws-sign4-tests"
  :licence "GNU General Public Licence 3.0"
  :depends-on (:aws-sign4)
  :components ((:module tests
                        :serial t
                        :components ((:file "package")
                                     (:file "test")))))

(defmethod perform ((o test-op) (c (eql (find-system '#:aws-sign4))))
  (operate 'load-op '#:aws-sign4-tests)
  (funcall (find-symbol (string :run-tests)
                        :aws-sign4-tests)))

