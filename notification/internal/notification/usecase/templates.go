package usecase

import (
	"fmt"
	"strings"

	"github.com/anAwesomeWave/simplified-vault/notification/internal/models"
)

// Тексты писем (ФТ-17). В письма попадают только поля событий: название
// секрета, адреса, IP, время и ссылки. Текста секрета в событиях нет, и
// шаблоны его не запрашивают.

const timeLayout = "2006-01-02 15:04:05 UTC"

const footer = `
-- 
Сервис передачи секретов. Письмо отправлено автоматически, отвечать на него не нужно.
`

// links строит ссылки на ручки API за gateway
type links struct {
	baseURL string // без завершающего "/"
}

func (l links) secret(e *models.Event) string {
	return l.baseURL + "/secrets/" + e.SecretID.String()
}

func (l links) requests(e *models.Event) string {
	return l.secret(e) + "/requests"
}

func titleOf(e *models.Event) string {
	if e.Title == "" {
		return "(без названия)"
	}
	return e.Title
}

// accessRequestedMessage - письмо автору: кто пытается открыть секрет,
// название секрета, ссылка на список запросов
func accessRequestedMessage(e *models.Event, l links) *models.Message {
	title := titleOf(e)
	var b strings.Builder
	fmt.Fprintf(&b, "Здравствуйте!\n\n")
	fmt.Fprintf(&b, "Пользователь %s пытается открыть ваш секрет «%s».\n\n", e.RequesterEmail, title)
	fmt.Fprintf(&b, "Запрос ждёт вашего решения. Список запросов:\n%s\n\n", l.requests(e))
	fmt.Fprintf(&b, "Одобрить или отклонить запрос: POST %s/%s с телом {\"decision\": \"approve\"} или {\"decision\": \"deny\"}.\n\n",
		l.requests(e), e.RequestID)
	fmt.Fprintf(&b, "Если вы не ждали этого запроса, отклоните его. Email в системе не подтверждается: "+
		"перед одобрением уточните по другому каналу, что запрос действительно отправлен с этого адреса.\n")
	b.WriteString(footer)
	return &models.Message{
		To:      e.OwnerEmail,
		Subject: fmt.Sprintf("Запрос доступа к секрету «%s»", title),
		Body:    b.String(),
	}
}

// accessDecidedMessage - письмо пользователю: решение автора и ссылка на секрет
func accessDecidedMessage(e *models.Event, l links) *models.Message {
	title := titleOf(e)
	var subject string
	var b strings.Builder
	fmt.Fprintf(&b, "Здравствуйте!\n\n")
	switch e.Decision {
	case models.DecisionApproved:
		subject = fmt.Sprintf("Доступ к секрету «%s» одобрен", title)
		fmt.Fprintf(&b, "Автор одобрил ваш доступ к секрету «%s».\n\n", title)
		fmt.Fprintf(&b, "Открыть секрет:\n%s\n\n", l.secret(e))
		fmt.Fprintf(&b, "Доступ действует до истечения срока жизни секрета или пока автор его не закроет.\n")
	default:
		subject = fmt.Sprintf("Доступ к секрету «%s» отклонён", title)
		fmt.Fprintf(&b, "Автор отклонил ваш запрос доступа к секрету «%s».\n\n", title)
		fmt.Fprintf(&b, "Секрет: %s\n\n", l.secret(e))
		fmt.Fprintf(&b, "Повторно запросить доступ к этому секрету нельзя.\n")
	}
	b.WriteString(footer)
	return &models.Message{
		To:      e.RequesterEmail,
		Subject: subject,
		Body:    b.String(),
	}
}

// secretViewedMessage - письмо автору: кто открыл, когда и с какого IP
func secretViewedMessage(e *models.Event, l links) *models.Message {
	title := titleOf(e)
	var b strings.Builder
	fmt.Fprintf(&b, "Здравствуйте!\n\n")
	fmt.Fprintf(&b, "Ваш секрет «%s» открыт.\n\n", title)
	fmt.Fprintf(&b, "Кто:   %s\n", e.ViewerEmail)
	fmt.Fprintf(&b, "Когда: %s\n", e.OccurredAt.Format(timeLayout))
	fmt.Fprintf(&b, "IP:    %s\n\n", e.IP)
	fmt.Fprintf(&b, "Запросы и история открытий:\n%s\n\n", l.requests(e))
	fmt.Fprintf(&b, "Если это открытие для вас неожиданно, закройте доступ этому пользователю или отзовите секрет, "+
		"а сам пароль или ключ смените в целевой системе.\n")
	b.WriteString(footer)
	return &models.Message{
		To:      e.OwnerEmail,
		Subject: fmt.Sprintf("Секрет «%s» открыт", title),
		Body:    b.String(),
	}
}

// accessRevokedMessages - письма пользователям, у которых закрыт доступ:
// название секрета и факт закрытия доступа. Одно письмо на адрес
func accessRevokedMessages(e *models.Event) []*models.Message {
	title := titleOf(e)
	var b strings.Builder
	fmt.Fprintf(&b, "Здравствуйте!\n\n")
	fmt.Fprintf(&b, "Ваш доступ к секрету «%s» закрыт: автор закрыл доступ или отозвал секрет.\n\n", title)
	fmt.Fprintf(&b, "Открыть этот секрет больше нельзя.\n")
	b.WriteString(footer)
	body := b.String()
	subject := fmt.Sprintf("Доступ к секрету «%s» закрыт", title)

	msgs := make([]*models.Message, 0, len(e.UserEmails))
	for _, to := range e.UserEmails {
		msgs = append(msgs, &models.Message{To: to, Subject: subject, Body: body})
	}
	return msgs
}
