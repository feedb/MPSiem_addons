# Unit тесты
## Запуск
Добавить переменные окружения:
- MP_CORE_HOSTNAME: IP/Hostname для доступа к MP CORE (без схемы http(s)) 
- MP_STORAGE_HOSTNAME: IP/Hostname для доступа к MP Storage (Elasticsearch) (без схемы http(s))
- MP_SIEM_HOSTNAME: IP/Hostname для доступа к MP SIEM Server (без схемы http(s))
- MP_LOGIN: учетная запись с ролью администратора в PT KB, IAM, SIEM
- MP_PASSWORD: пароль
- При запуске выставить директорию запуска: mpsiemlib

# Особенности
- Все тесты используют LDAP учетную запись. Сменить поведение можно в tests/settings.py
- Далеко не все тесты имеют строгие проверки возвращаемых данных.

## Events
- Для выборки событий используют интервал в 60 сек, для группировки в 3600 сек. Если у вас нет событий в этом интервале, тесты провалятся.

## Tables
- test_Tables_set_table_data – использует захардкоженное имя табличного списка.

## KB
- Тесты KB долгие, т.к. есть проверки установки и удаления контента в/из SIEM. Тест дожидается завершения выполнения операции, делая проверки статуса каждые 10 сек и так 6 раз. Если KB нагружен, то тест может не успеть и завершится с ошибкой
- Тесты KB могут провалиться, если нет deploy базы или она пуста.