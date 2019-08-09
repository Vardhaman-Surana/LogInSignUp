package LoginSignup

import (
	"errors"
	"fmt"
	"net/smtp"
)

var errNotSent = errors.New("verification mail not sent ")

func SendMail(receiver string, token string) error {
	sender := "Email id to send email"
	pass := "password for the above id"
	from := fmt.Sprintf("From: <%s>\r\n", sender)
	to := fmt.Sprintf("To: <%s>\r\n", receiver)
	subject := fmt.Sprintf("Subject: Verification Email\r\n")
	body := fmt.Sprintf("To verfiy your email visit the below link\r\n http://192.168.29.205:4200/auth/emailVerify/%s", token)
	msg := from + to + subject + "\r\n" + body

	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", sender, pass, "smtp.gmail.com"),
		sender, []string{receiver}, []byte(msg))

	if err != nil {
		fmt.Printf("%v", err)
		return errNotSent
	}
	return nil
}
