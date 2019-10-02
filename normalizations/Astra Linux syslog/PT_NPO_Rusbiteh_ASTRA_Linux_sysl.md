PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login_invalid_user

https://siem-core.local.tst:8091/#/siem/normalization-rules?folderId=2bf21210-46a1-4e12-9a77-5ba3f4ef955f:rule

# Dec  3 11:25:42 astra-1-4-se fly-dm: :0[6003]: pam_parsec_mac(fly-dm:auth): Unknown user qwe

TEXT = '{"<"NUMBER">"?}{":"?} {time=DATETIME} {event_src.ip=IPV4|event_src.ip=IPV6|event_src.hostname=HOSTNAME|"(none)"|}
        fly-dm: :{NUMBER}[{NUMBER}]: pam_parsec_mac(fly-dm:auth): Unknown user {subject.name=WORDDASH}'

subject = "account"
object = "system"
action = "login"
status = "failure"

src.ip = event_src.ip
src.hostname = event_src.hostname
dst.ip = event_src.ip
dst.hostname = event_src.hostname

reason = "Invalid user"

importance = "info"

category.generic = "Access"
category.high = "Authentication"
category.low = "Local"

event_src.title = "astra_linux"
event_src.vendor = "npo_rusbiteh"
event_src.category = "Operating system"

id = "PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login_invalid_user"

---

Основные параметры

Системное название
    graphical_login_invalid_user

Идентификатор
    PT-NF-3004

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

PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login_invalid_user_action_login_subject_account_status_failure
Критерии
id = "PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login_invalid_user" and action = "login" and subject = "account" and status = "failure"
ENG
The user {subject.name} failed to log in to host {event_src.host}
RUS
Пользователю {subject.name} не удалось осуществить вход в систему на узле {event_src.host}
