package models

// Message - одно письмо одному получателю.
//
// Subject и Body - обычный текст в UTF-8; кодирование заголовков и тела
// (RFC 2047, quoted-printable) - забота отправителя писем
type Message struct {
	// ID уникален для письма и стабилен между повторами отправки одного события:
	// из него строится заголовок Message-ID
	ID      string
	To      Email
	Subject string
	Body    string
}
