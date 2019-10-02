PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login

https://siem-core.local.tst:8091/#/siem/normalization-rules?folderId=1e756b30-da9a-45f5-8d1f-2a70d1ddeb49:rule

# Nov 30 09:19:47 astra-1-4-se fly-dm: :0[3129]: pam_unix(fly-dm:session): session opened for user ekoz by (uid=0)
# Nov 30 09:24:18 astra-1-4-se fly-dm: :0[3339]: pam_unix(fly-dm:session): session opened for user root by (uid=0)

TEXT = '{"<"NUMBER">"?}{":"?} {time=DATETIME} {event_src.ip=IPV4|event_src.ip=IPV6|event_src.hostname=HOSTNAME|"(none)"|}
        fly-dm: :{NUMBER}[{NUMBER}]: pam_unix(fly-dm:session): session opened for user {subject.name=WORDDASH} by {"("}uid={subject.id=NUMBER}{")"} '

subject = "account"
object = "system"
action = "login"
status = "success"

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

id = "PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login"

---

Основные параметры

Системное название
    graphical_login

Идентификатор
    PT-NF-3002

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

    User was logged on host with graphical interface

Описание

    User was logged on host with graphical interface

---

Правила локализации
Развернуть все | Свернуть все

PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login_action_login_subject_account_status_success

Критерии
id = "PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_login" and action = "login" and subject = "account" and status = "success"

ENG
The user {subject.name} successfully logged in to host {event_src.host}

RUS
Пользователь {subject.name} осуществил успешный вход в систему на узле {event_src.host}

