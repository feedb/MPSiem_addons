##############################################################
#                                                            #
#         take perfomance counters and form the json data    #
#       generate process name from linked service by ID      #
#                                                            #
##############################################################


#EN Codepage
$counter_id_path = '\Process(*)\id process'
$CounterRoot = "Process(*)"
#$CounterList = "% Processor Time","% User Time","Thread Count","Working Set","Working Set - Private","% Priveleged Time", "IO Read Bytes/sec", "IO Write Bytes/sec", "IO Write Operations/sec","IO Read Operations/sec"
$CounterList = "Working Set"


<#
#RU Codepage
$counter_id_path = '\Процесс(*)\Идентификатор процесса'
$CounterRoot = "Процесс(*)"
$CounterList = "% загруженности процессора","Счетчик потоков"
#>

# Формируем хэш-таблицу (словарь) "[int]ID процесса:[string]Имя сервиса".
$start=get-date
$dict_svc = $null
$dict_svc = @{}
Get-WmiObject -Class Win32_Service  -Filter "ProcessId > 0" | 
Select ProcessID, Name, PathName  | ?{ if (-not ($dict_svc.ContainsKey([int]$_.ProcessID))) 
             {
              $dict_svc.add( [int]$_.ProcessID,
                             @{name = [string]$_.Name
                               Path = [string]$_.PathName}
                            )}
             }



#Формируем хэш-таблицу (словарь) из запроса к каунтеру где ключ - имя процесса, а значение имя связанного череp ID сервиса (если есть) либо то же имя процесса
$dict_proc = $null
$dict_proc = @{}

(Get-Counter $counter_id_path -ErrorAction SilentlyContinue).CounterSamples | ?{ 
             $proc_name=[string]($_.Path -Replace '^.*\((.*)\).*$','$1')
             #$proc_name=[string]($_.Path)
             #$svc_name = $proc_name -Replace '^.*\((.*)\).*$','$1'
             $proc_id = [int]$_.CookedValue
             if (-not ($dict_proc.ContainsKey([string]$proc_name))) {
                  #if ($dict_svc.ContainsKey($proc_id)) {$svc_name=$dict_svc[$proc_id].name}
                  $dict_proc.add($proc_name, $proc_id)
                  }
             }
#$dict_proc 

#Опросить все каунтеры по списку. 
# Обработать полученный список. По имени процесса берем из словаря каунтеров ID по этому ID ищем, если ли служба. если есть - пишем в instance имя службы. Если нет - пишем имя процесса
# {proc_name = $_.Path -Replace '^.*\((.*)\).*$','$1'} имя процесса
# { @{n=$counter_name; e={[double]$_.CookedValue}} имя параметра - имя каунтера. Значение - значение метрики
# {instance = (либо proc_name либо имя сервиса если есть}
# При запросе каунтеров добавлять вычисляемое поле insctance: по имени #процесса берем ID. ПО Id тащим имя и пишем в instance
#для каждого каунтера из конфига, собираем данные и формируем JSON
#$dict_proc
#$dict_svc

#добавляем ко всему списку счетчиков имя коренвого перфкаунтера, формируем полный путь

function ProcessTo-Service {
    param ([string]$Process_name)
    $Process_name = $Process_name -Replace '^.*\((.*)\).*$','$1'
    $Service_name = $Process_name
    $Service_path = "None"
    
    if ($dict_proc.ContainsKey([string]$Process_name)) 
           {
                  $proc_id=$dict_proc[$Process_name]
                  if ($dict_svc.ContainsKey($proc_id)) 
                  {
                                   $Service_name =$dict_svc[$proc_id].name
                                   $Service_path =$dict_svc[$proc_id].Path
                  }
             }
    
      
      $OutObject = [PSCustomObject]@{ServiceName = $Service_name
                                     CmdLine = $Service_path
                                     }
     $OutObject
     }


$counter_data=@()
$start
foreach($counter in $CounterList) {
$CounterPath = "\"+$CounterRoot +"\"+$counter
$counter_data+=(Get-Counter $CounterPath -ErrorAction SilentlyContinue).CounterSamples | select -Property @{n='proc_name';e={[string]$_.Path-Replace '^.*\((.*)\).*$','$1'}}, 
                                                             @{n=$counter;e={[double]$_.CookedValue}}, 
                                                             @{n="instance";e={(ProcessTo-Service($_.Path)).ServiceName}},
                                                             @{n="cmdline";e={(ProcessTo-Service($_.Path)).CmdLine}}


}
$counter_data  | ConvertTo-Json
