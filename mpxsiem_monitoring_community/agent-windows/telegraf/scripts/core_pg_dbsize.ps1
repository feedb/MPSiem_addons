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
$query = "SELECT datname,pg_database_size(datname) FROM pg_database"
Set-Location -Path $config.psqlpath

$data=.\psql.exe -c $query -U $config.pguser -d "postgres" -t -A | ConvertFrom-Csv -Delimiter "|" -Header "dbname","size" | select -Property @{n='dbname';e={[string]$_.dbname}}, @{n='size';e={[long]$_.size}} 
$data | ConvertTo-Json -Depth 3 -Compress
