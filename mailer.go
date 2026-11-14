package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Mailer sends plain-text e-mail over SMTP (STARTTLS on 587, or implicit TLS on 465).
// Configure with SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM. Any provider works
// (Gmail with an app password, Brevo, Resend SMTP, Mailgun, your own server ...).
type Mailer struct{ Host, Port, User, Pass, From string }

func mailerFromEnv() *Mailer {
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	if host == "" {
		return nil
	}
	m := &Mailer{Host: host, Port: mustEnv("SMTP_PORT", "587"), User: os.Getenv("SMTP_USER"), Pass: os.Getenv("SMTP_PASS"), From: os.Getenv("SMTP_FROM")}
	if m.From == "" {
		m.From = m.User
	}
	return m
}

func (m *Mailer) Send(to, subject, body string) error {
	if strings.ContainsAny(to+m.From+subject, "\r\n") {
		return errors.New("invalid header characters")
	}
	from, err := mail.ParseAddress(m.From)
	if err != nil {
		return fmt.Errorf("SMTP_FROM: %w", err)
	}
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("recipient: %w", err)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(m.Host, m.Port), 15*time.Second)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(40 * time.Second))
	if m.Port == "465" {
		conn = tls.Client(conn, &tls.Config{ServerName: m.Host})
	}
	c, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if m.Port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: m.Host}); err != nil {
				return err
			}
		} else if m.User != "" {
			return errors.New("server does not offer STARTTLS; refusing to send credentials in clear text")
		}
	}
	if m.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.User, m.Pass, m.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(rcpt.Address); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	hdr := "From: " + from.String() + "\r\nTo: " + rcpt.String() + "\r\nSubject: " + mime.QEncoding.Encode("utf-8", subject) +
		"\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
	if _, err := io.WriteString(w, hdr); err != nil {
		return err
	}
	qp := quotedprintable.NewWriter(w)
	if _, err := io.WriteString(qp, body); err != nil {
		return err
	}
	_ = qp.Close()
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// sendResetMail delivers the reset link. Without SMTP (local demo) the link is printed to the
// server console instead, so the flow can still be shown end to end.
func sendResetMail(m *Mailer, to, link, lang string) {
	subject := "Reset your Crimson password"
	body := "Someone asked to reset the password for this e-mail address on Crimson.\n\n" +
		"Open this link within 1 hour to choose a new password:\n\n" + link + "\n\n" +
		"If this was not you, ignore this message. Your password stays the same.\n"
	if lang == "az" {
		subject = "Crimson parolunuzu sıfırlayın"
		body = "Kimsə Crimson-da bu e-poçt ünvanı üçün parolun sıfırlanmasını istədi.\n\n" +
			"Yeni parol seçmək üçün 1 saat ərzində bu linki açın:\n\n" + link + "\n\n" +
			"Bu siz deyildinizsə, bu mesajı nəzərə almayın. Parolunuz dəyişməz.\n"
	}
	if m == nil {
		log.Printf("password reset for %s (SMTP not configured, link printed instead): %s", to, link)
		return
	}
	if err := m.Send(to, subject, body); err != nil {
		log.Printf("password reset e-mail to %s failed: %v", to, err)
	}
}
