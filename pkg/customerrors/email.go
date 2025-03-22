package customerrors

import "errors"

var ErrGomailUncryptedConnection = errors.New("gomail: unencrypted connection")
var ErrGomailWrongHostName = errors.New("gomail: wrong host name")
var ErrGomailExpectedAuth = errors.New("gomail: unexpected server challenge")
var ErrEmailTimeout = errors.New("unable to send mail because of timeout")
var ErrEmailAuth = errors.New("unable to authenticate email server")
