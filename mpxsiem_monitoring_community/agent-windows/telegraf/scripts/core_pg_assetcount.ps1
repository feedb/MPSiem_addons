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
$query = "SELECT COUNT(*)  FROM public.asset_infos WHERE is_closed = false"

.\psql -c `"$query`" -U $config.pguser -d maxpatrol_assets_processing -t -A |
select -Property @{n='assest_count';e={[long]$_}} |  ConvertTo-Json  -Compress


