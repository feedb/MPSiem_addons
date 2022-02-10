sc stop telegraf
sc delete telegraf
ping 127.0.0.1 -n 3 >nul
REG DELETE HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\telegraf  /f
"C:\telegraf\telegraf.exe" --config "C:\telegraf\telegraf.conf" --config-directory C:\telegraf\telegraf.d  --service install
sc config telegraf start= delayed-auto
sc start telegraf
