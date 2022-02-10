
$ErrorActionPreference = "Continue"
$current_folder = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)


if (-not (Test-Path "$current_folder\scripts.conf" -PathType Leaf)) {
     Write-Host "`nERROR: the file scripts.conf is not found in ""$current_folder"""
      exit(1)
      }

$config = (get-content "$current_folder\scripts.conf" | ConvertFrom-Json )
$siem = $config.siem_address


$get_table_info_uri='http://'+$config.siem_address+':8013/v2/control/tables'
(Invoke-WebRequest -Uri $get_table_info_uri -UseBasicParsing).content 
