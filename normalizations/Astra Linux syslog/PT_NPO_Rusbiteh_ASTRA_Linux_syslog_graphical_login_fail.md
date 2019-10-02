PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login_fail

https://siem-core.local.tst:8091/#/siem/normalization-rules?folderId=d2a9eccd-7b2e-431a-aa31-b9da069519a0:rule

# Dec 1 10:32:45 astra-1-4-se fly-dm: :0[25962]: pam_unix(fly-dm:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost= user=root
# Dec 1 10:34:07 astra-1-4-se fly-dm: :0[25962]: pam_unix(fly-dm:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost= user=ekoz

TEXT = '{"<"NUMBER">"?}{":"?} {time=DATETIME} {event_src.ip=IPV4|event_src.ip=IPV6|event_src.hostname=HOSTNAME|"(none)"|}
        fly-dm: :{NUMBER}[{NUMBER}]: pam_unix(fly-dm:auth): {reason="authentication failure"}; logname={WORDDASH?} uid={subject.id=NUMBER} euid={NUMBER} tty=:{NUMBER} ruser={WORDDASH?} rhost={WORDDASH?} user={subject.name=WORDDASH}'

subject = "account"
object = "system"
action = "login"
status = "failure"

src.ip = event_src.ip
src.hostname = event_src.hostname
dst.ip = event_src.ip
dst.hostname = event_src.hostname

importance = "info"

category.generic = "Access"
category.high = "Authentication"
category.low = "Local"

event_src.title = "astra_linux"
event_src.vendor = "npo_rusbiteh"
event_src.category = "Operating system"

id = "PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login_fail"

---

Основные параметры

Системное название
    graphical_login_fail

Идентификатор
    PT-NF-3003

Тип
    Системный

Источник
    Positive Technologies 

Папка
    syslog

Группы
    не задано 

Статус валидации

Статус установки
    Установлено 

---

Локализация

Название

    User failed to logon on host with graphical interface

Описание

    User failed to logon on host with graphical interface

---

Правила локализации
Развернуть все | Свернуть все

PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login_fail_action_login_subject_account_status_failure
Критерии
id = "PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login_fail" and action = "login" and subject = "account" and status = "failure"
ENG
The user {subject.name} failed to log in to host {event_src.host}
RUS
Пользователю {subject.name} не удалось осуществить вход в систему на узле {event_src.host}
