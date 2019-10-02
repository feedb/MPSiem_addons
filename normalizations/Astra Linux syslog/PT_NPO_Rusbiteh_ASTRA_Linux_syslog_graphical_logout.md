PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_logout

https://siem-core.local.tst:8091/#/siem/normalization-rules?folderId=8f6ef0cc-7b45-463a-a11b-ecf3b3b6e17c:rule

# Nov 30 09:22:39 astra-1-4-se fly-dm: :0[3129]: pam_unix(fly-dm:session): session closed for user ekoz
# Dec 1 09:58:19 astra-1-4-se fly-dm: :0[3339]: pam_unix(fly-dm:session): session closed for user root

TEXT = '{"<"NUMBER">"?}{":"?} {time=DATETIME} {event_src.ip=IPV4|event_src.ip=IPV6|event_src.hostname=HOSTNAME|"(none)"|}
        fly-dm: :{NUMBER}[{NUMBER}]: pam_unix(fly-dm:session): session closed for user {subject.name=WORDDASH}'

subject = "account"
object = "system"
action = "logout"
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

id = "PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_logout"

---


Основные параметры

Системное название
    graphical_logout

Идентификатор
    PT-NF-3005

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

    User logout from host with graphical interface

Описание

    User logout from host with graphical interface

---

Правила локализации
Развернуть все | Свернуть все

PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_logout_action_logout_subject_account_status_success
Критерии
id = "PT_NPO_Rusbiteh_ASTRA_Linux_syslog_graphical_logout" and action = "logout" and subject = "account" and status = "success"

ENG
The user {subject.name} logged out from host {event_src.host}

RUS
Пользователь {subject.name} осуществил выход из системы на узле {event_src.host}
