;;;;; adminbot.lisp

(in-package #:adminbot)

;;; A bot to perform admin tasks for a matrix server

(defclass adminbot (client auto-joiner message-log)
  ((registration-shared-secret
    :accessor registration-shared-secret
    :initarg :registration-shared-secret
    :initform nil)))

(defvar *adminbot* nil)

(setf (registration-shared-secret *adminbot*) "googa")

(defmethod handle-event :after ((*adminbot* adminbot) (event text-message-event))
  (handle-invite-request (ppcre:split " " (msg-body event))))

(defparameter +register-path+ "/_matrix/client/r0/admin/register")

(defun handle-invite-request (words)
  (when (string= (first words) "!invite")
    (let* ((path (granolin::make-matrix-path *adminbot* +register-path+))
           (username (cadr words))
           (password (generate-password))
           (nonce (get-nonce path))
           (homeserver (granolin::homeserver *adminbot*))
           (user-id (make-user-id username homeserver)))
      (cond
        ((not (valid-username-p username)) (send-text-message *adminbot* *room-id* +invalid-username-message+))
        ((not (valid-user-id-p user-id)) (send-text-message *adminbot* *room-id* +invalid-user-id-message+))
        (t  (progn
              (send-text-message *adminbot* *room-id*
                                 (format nil "Inviting ~a to this server with ~a for their password." username password))
              (multiple-value-bind (body status headers)
                  (register path (registration-shared-secret *adminbot*) username password)
                (if (= 200 status)
                    (send-text-message *adminbot* *room-id* "Success! Send your friend their login details!")
                    (send-text-message *adminbot* *room-id*
                                       (format nil "Something failed, contact a server admin."))))))))))

;; The localpart of a user ID is an opaque identifier for that user.
;; It MUST NOT be empty, and MUST contain only the characters a-z, 0-9, ., _, =, -, and /.

(defconstant +username-chars+ "0123456789abcdefghijklmnopqrstuvwxyz-.=_/")

(defun valid-username-p (username)
  (unless (= 0 (length username))
    (every (lambda (char) (find char +username-chars+)) username)))

(defconstant +invalid-username-message+
  "Invalid username. Please retry with !invite <username>. The username must be present, and  contain only the characters a-z, 0-9, ., _, =, -, and /.")

;; The length of the entire user ID including the @ signifier and the domain MUST NOT exceed 255 characters

(defun valid-user-id-p (user-id)
  (<= (length user-id) 255))

(defun make-user-id (username homeserver)
  (concatenate 'string "@" username ":" homeserver))

(defconstant +invalid-user-id-message+
  "Your username is too long, please choose something shorter.")

(defun get-nonce (url)
  "Requests the cryptographic nonce from the registration endpoint."
  (multiple-value-bind (body status headers)
      (drakma:http-request url :external-format-out :utf-8 :external-format-in :utf-8)
    (getf (jonathan:parse (flexi-streams:octets-to-string body :external-format :utf8)) :|nonce|)))

(defun bytes (str)
  "Convienence function to convert STR to a byte array"
  (ironclad:ascii-string-to-byte-array str))

(defun partial (f &rest args)
  "currying function"
  (lambda (&rest more-args)
    (apply f (append args more-args))))

(defun generate-password ()
  "Generates a random list of characters "
  (concatenate 'string (loop :for x :upto 10
        :collect (elt "ACDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" (random 62)))))

(defun hmac-digest-string (secret nonce user password)
  "Creates the hmac digest required to authenticate the registration request."
  (let* ((mac (ironclad:make-hmac (bytes secret) :sha1))
         (nul (format nil "~C" (code-char 0)))
         (data (mapcar #'bytes (list nonce nul user nul password nul "notadmin"))))
    (mapc (partial #'ironclad:update-hmac mac) data)
    (ironclad:byte-array-to-hex-string (ironclad:hmac-digest mac))))

(defun register (url secret username password)
  "Posts a JSON payload to the matrix admin registration URL create a new user."
  (let* ((nonce (get-nonce url))
         (mac (hmac-digest-string secret nonce username password))
         (content (list :|nonce| nonce :|username| username :|password| password :|mac| mac :|admin| nil)))
    (drakma:http-request url :method :post
                             :external-format-out :utf-8
                             :external-format-in :utf-8
                             :content-type "application/json"
                             :content (jonathan:to-json content))))

(defun start-adminbot ()
  "A start function to pass in as the :toplevel to SAVE-LISP-AND-DIE"
  (make-random-state)
  (let* ((config (if (uiop:file-exists-p "adminbot.config")
                     (with-open-file (input "adminbot.config")
                       (read input))
                     (progn (format  t "I think you need a adminbot.config~%~%")
                            (return-from start-adminbot))))
         (bot (make-instance 'adminbot
                             :ssl (if (member :ssl config)
                                      (getf config :ssl)
                                      t)
                             :hardcopy (getf config :hardcopy)
                             :user-id (getf config :user-id)
                             :homeserver (getf config :homeserver)
                             :registration-shared-secret (getf config :registration-shared-secret))))
    (when (not (logged-in-p bot))
      (login bot (getf config :user-id) (getf config :password)))
    (start bot)))

