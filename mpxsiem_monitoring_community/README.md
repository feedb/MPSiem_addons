Мониторинг MaxPatrol SIEM
Набор конфиг-файлов для telegraf агентов и готовые дашборды для Grafana.

### Пререквизиты:
*  Установленный и настроенный сервер [Grafana](https://grafana.com/grafana/download)
*  Установленная и настроенная база данных [Influxdb](https://portal.influxdata.com/downloads)
*  Создана база данных в [inxlufb](https://docs.influxdata.com/influxdb/v1.7/introduction/getting-started/) Для примера, возьмем "telegraf"
*  В grafana cоздан [datasource](https://grafana.com/docs/features/datasources/influxdb/)
*  Для debian сервера: `apt-get install sysstat` и затем `service sysstat start`

### DEBIAN Установка и настройка telegraf агента:
1.  Качаем телеграф агента из [GitHub](https://github.com/influxdata/telegraf/releases)
```    
    рекомендован 1.18.2: wget https://dl.influxdata.com/telegraf/releases/telegraf_1.18.2-1_amd64.deb    
```    
2.  Устанавливаем сервис telegraf агента:
```
    dpkg -i telegraf_1.18.2-1_amd64.deb
```    
3.  В файле конфигурации устанавливаем пользователя root в параметр user (либо выдать расширенные права доступа для пользователя telegraf) 
``` 
    sed -r -i 's/User=.*$/User=root/g'  /lib/systemd/system/telegraf.service
    systemctl daemon-reload
    systemctl restart telegraf.service
```    
4.  В зависимости от установленных компонентов MPX (siem, storage, agent) скопироуйте соответсвующие config файлы из папки ./configs в /etc/telegraf/telegraf.d
5.  Снять комментарий в файле /etc/telegraf/telegraf.conf с тегов соответствующих установленным компонентам
6.  В файле /etc/telegraf/telegraf.conf установить параметры с адресом influxDB и именем базы данных
```
    urls = ["http://<INFLUX ADDRESS>:8086"]
    database = "<DATABASE NAME>"
```    
7. Перезапустите сервис telegraf
```
   systemctl restart telegraf.service   
```   

### WINDOWS Установка и настройка telegraf агента:
1.  Скопировать содержимое .\agent-windows\telegraf в папку C:\telegraf 
2.  Скачать исполняемый файл агента из [GitHub](https://github.com/influxdata/telegraf/releases) и поместить в папку C:\telegraf
```    
    рекомендован 1.18.2: https://dl.influxdata.com/telegraf/releases/telegraf-1.18.2_windows_amd64.zip   
```    
3.  В зависимости от установленных компонентов MPX (siem, storage, agent, core) скопироуйте соответсвующие config файлы из папки ./configs в C:\telegraf\telegraf.d
4.  Снять комментарий в файле C:\telegraf\telegraf.conf с тегов соответствующих установленным компонентам
5.  В файле C:\telegraf\telegraf.conf установить параметры с адресом influxDB и именем базы данных
```
    urls = ["http://<INFLUX ADDRESS>:8086"]
    database = "<DATABASE NAME>"
```    
6. Запустите регистрацию telegraf как сервиса windows
```
   C:\telegraf\register_telegraf.cmd   
```   

### Импортируем все дашборды из проекта в графану:
* [Импорт дашборда в графану](https://grafana.com/docs/reference/export_import/#importing-a-dashboard)
