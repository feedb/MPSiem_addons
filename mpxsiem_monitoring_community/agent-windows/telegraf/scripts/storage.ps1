####################################################################################
#                                                                                  #
#  return win ElsatiSearch health data in "telegraf.inputs for debian" format      #
#                                                                                  #
####################################################################################


$ErrorActionPreference = "Continue"
$current_folder = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)

if (-not (Test-Path "$current_folder\scripts.conf" -PathType Leaf)) {
     Write-Host "`nERROR: file scripts.conf not found in ""$current_folder"""
      exit(1)
      }

$config = (get-content "$current_folder\scripts.conf" | ConvertFrom-Json )

$health_get='http://'+$config.es_address+':9200/_cluster/health'

$map_health =@{
     red = 3
     yellow = 2
     green = 1
     }

$health = (Invoke-WebRequest -Uri $health_get -UseBasicParsing).content | ConvertFrom-Json
$status_code = 4
if ( $map_health.ContainsKey($health.status) ) { 
           $status_code = $map_health[$health.status]
           }
$health | add-member -Name "status_code" -Value $status_code -MemberType NoteProperty 
$health | ConvertTo-Json


