Мониторинг MaxPatrol SIEM
Набор конфиг-файлов для telegraf агентов и готовые дашборды для Grafana.

Пререквизиты:
*  Установленный и настроенный сервер Grafana: https://grafana.com/grafana/download
*  Установленная и настроенная база данных Influxdb: https://portal.influxdata.com/downloads
*  [Создана база данных в inxlufb](https://docs.influxdata.com/influxdb/v1.7/introduction/getting-started/) Для примера, возьмем telegraf
*  Создан datasource в Grafana: https://grafana.com/docs/features/datasources/influxdb/
*  Для linux сервера: `apt-get install sysstat` и затем `service sysstat start`

Настройка конфигов telegraf агентов:
1.  Берем нужный конфиг телеграф агента telegraf.conf (для Windows или для Linux) и редактируем его содержимое (только секцию OUTPUTS):
    *  Меняем плейсхолдер {{influxdb_address}} на ip адрес или fqdn вашего influxdb сервера
    *  Если имя вашей бд не telegraf, то меняем database = "your_database"
    *  Если вы включили аутентификацию для БД, то меняем значения на ваши  `username = "influxdb_username" password = "influxdb_password"`


Установка telegraf агента:
1.  Качаем последнюю версию телеграф агента для вашей операционной системы: https://portal.influxdata.com/downloads/
2.  Устанавливаем сервис telegraf агента:
    *  Для Windows:
       1.   Распаковываем файлы агента в папку, например C:\telegraf
       2.   Заменяем предварительно настроенный конфиг telegraf.conf из данного репозитория
       3.   Выполняем установку и запуск сервиса:
            *  `"C:\telegraf\telegraf.exe" --config "C:\telegraf\telegraf.conf" --service install`
            *  `sc config telegraf start= delayed-auto`
            *  `sc start telegraf`
       4.   Копируем папки: telegraf.d и scripts с файлами из проекта, в папку C:\telegraf
    *   Для Linux:
       1.   Команда для установки представлена по ссылке https://portal.influxdata.com/downloads/ в п.1
       2.   Заменяем предварительно настроенный конфиг telegraf.conf из данного репозитория в /etc/telegraf
       3.   Копируем файлы конфигурации из папки telegraf.d в /etc/telegraf/telegraf.d на агенте
       3.   Перезапускаем сервис:
            *  `service telegraf restart`

Импортируем все дашборды из проекта в графану:
При импорте дашборда выбираем ранее созданный datasource influxdb.
* [Импорт дашборба в графану](https://grafana.com/docs/reference/export_import/#importing-a-dashboard)
