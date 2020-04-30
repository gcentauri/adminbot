;;;; adminbot.asd

(asdf:defsystem #:adminbot
  :description "A Matrix bot to do admin tasks."
  :author "Shoshin <shshoshin@protonmail.com>"
  :license  "AGPL"
  :version "0.0.1"
  :serial t
  :depends-on (#:granolin #:ironclad #:cl-ppcre)
  :components ((:file "package")
               (:file "adminbot")))
