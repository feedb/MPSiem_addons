####################################################################################
#                                                                                  #
#                    get FPTA dbs statistic from mdbx_stat.exe tools               #
#                                                                                  #
####################################################################################


$ErrorActionPreference = "SilentlyContinue"
$current_folder = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)

if (-not (Test-Path "$current_folder\scripts.conf" -PathType Leaf)) {
     Write-Host "`nERROR: the file scripts.conf is not found in ""$current_folder"""
      exit(1)
      }
$config = (get-content "$current_folder\scripts.conf" | ConvertFrom-Json )

if (-not (Test-Path $config.fpta_exe_path\mdbx_stat.exe -PathType Leaf)) {
     Write-Host "`nERROR: mdbx_stat.exe not found in"$config.fpta_exe_path"Check value ""fpta_exe_path in ""scripts.conf"" file"
      exit(2)
      }


Set-Location -Path $config.fpta_exe_path
foreach ($db in $config.fpta_dbs)
    {
    $db_path =  $config.fpta_db_path+"`\"+$db
    #получаем вывод команды mdbx_stat.exe, убираем лишнее и раскладываем на список объектов, где поле name - имя параметра
    $output_rows =( (.\mdbx_stat.exe -ef $db_path).trim() | where {$_ -like "*: *"}).replace(": ",":") |
    ConvertFrom-Csv -Delimiter ":" -Header "name", "raw_data" | 
    select -Property @{n='fpta_param';e={[string]$_.name}}, 
    @{n='raw_data';e={[string]$_.raw_data}}, 
    @{n='value'; e={[long]0}} , 
    @{n='percent';e={[double]0}},
    @{n='fpta_db';e={[string]$db}}
    #поле raw_data содержит неформатированную строку данных. Раскладываем, в зависимости от содержимого, по value и percent
    foreach($row in $output_rows) 
        {
         $row.fpta_param =  $row.fpta_param.replace(" ","_")
         if($row.raw_data -match '[0-9]+') {  [long]$row.value = $matches[0]}
         if($row.raw_data -match '([0-9.]+)(?=\%)') {  $row.percent = [double]$matches[0]}
         }
    $all_results = @($all_results) +  $output_rows
    }  

 $all_results | ConvertTo-Json
   