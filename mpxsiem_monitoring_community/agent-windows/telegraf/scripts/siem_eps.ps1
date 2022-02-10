$ErrorActionPreference = "Continue"
$current_folder = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)


if (-not (Test-Path "$current_folder\scripts.conf" -PathType Leaf)) {
     Write-Host "`nERROR: the file scripts.conf is not found in ""$current_folder"""
      exit(1)
      }

$config = (get-content "$current_folder\scripts.conf" | ConvertFrom-Json )
$siem = $config.siem_address


$raw_addr='http://'+$config.siem_address+':8013/events/counter/simple?name=storage.events_raw.in&granularity=300&aggregation=avg'
$norm_addr='http://'+$config.siem_address+':8013/events/counter/simple?name=storage.events_norm.in&granularity=300&aggregation=avg'
$corrin_addr='http://'+$config.siem_address+':8013/events/counter/simple?name=correlator.events.in&granularity=300&aggregation=avg'
$corrout_addr='http://'+$config.siem_address+':8013/events/counter/simple?name=correlator.events.out&granularity=300&aggregation=avg'

$data_collector = @( @{raw_eps=0}, @{norm_eps=0}, @{corr_in=0}, @{corr_out=0})

$value = ( (Invoke-WebRequest -Uri $raw_addr -UseBasicParsing).content | ConvertFrom-Json).count
$data_collector[0].raw_eps = [math]::Round($value[-2])


$value = ( (Invoke-WebRequest -Uri $norm_addr -UseBasicParsing).content | ConvertFrom-Json).count
$data_collector[1].norm_eps = [math]::Round($value[-2])


$value = ( (Invoke-WebRequest -Uri $corrin_addr -UseBasicParsing).content | ConvertFrom-Json).count
$data_collector[2].corr_in = [math]::Round($value[-2])


$value = ( (Invoke-WebRequest -Uri $corrout_addr -UseBasicParsing).content | ConvertFrom-Json).count
$data_collector[3].corr_out = [math]::Round($value[-2])


$data_collector | ConvertTo-Json -Compress
