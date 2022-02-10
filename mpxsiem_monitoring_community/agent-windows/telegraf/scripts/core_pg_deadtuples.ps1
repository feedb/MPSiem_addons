$ErrorActionPreference = "SilentlyContinue"
$current_folder = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)

if (-not (Test-Path "$current_folder\scripts.conf" -PathType Leaf)) {
     Write-Host "`nERROR: file scripts.conf not found in ""$current_folder"""
      exit(1)
      }

$config = (get-content "$current_folder\scripts.conf" | ConvertFrom-Json )

if (-not (Test-Path $config.psqlpath\psql.exe -PathType Leaf)) {
     Write-Host "`nERROR: psql.exe not found in ""$psqlpath"" Check value psqlpath in ""scripts.conf"" file"
      exit(2)
      }

$env:PGPASSWORD=$config.pgpass
Set-Location -Path $config.psqlpath
$query = "SELECT sum (n_dead_tup) AS dead_tuples FROM pg_stat_all_tables"

#Фомируем массив пар {база данных, dead_tuples = 0}
$databases = .\psql -c "SELECT datname FROM pg_database WHERE datistemplate = false" -U $config.pguser -d postgres -t -A | 
ConvertFrom-Csv  -Header "dbname" | select -Property @{n='dbname';e={[string]$_.dbname}},  @{n='dead_tuples';e={[long]0}}
#Заполняем массив значениями для dead_tuples
$databases | foreach-Object { $_.dead_tuples=.\psql.exe -c $query -U $config.pguser -d $_.dbname -t -A }  
#Формируем вывод JSON для telegraf aгента
$databases | select -Property @{n='dbname';e={[string]$_.dbname}},  @{n='dead_tuples';e={[long]$_.dead_tuples}} | ConvertTo-Json -Depth 3 -Compress

