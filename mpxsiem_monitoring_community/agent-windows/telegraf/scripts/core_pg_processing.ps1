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
$jsonpath = "$current_folder\core_pg_processing"
Set-Location -Path $config.psqlpath

Get-ChildItem "$jsonpath" -Filter "*.json" | Foreach-Object { $json_data = Get-Content $_.FullName | ConvertFrom-Json 
       
       $json_data.query1 = $json_data.query1 -replace('"','""') 
       $json_data.query2 = $json_data.query2 -replace('"','""') 
       
       $query1_val = .\psql.exe -c $json_data.query1 -U $config.pguser -d $json_data.database1 -t -A
       $json_data.query2= $json_data.query2 -replace ("{query1}", $query1_val)
       
       
       if ($json_data.query1 -eq $json_data.query2) {$query2_val = $query1_val }
       else { $query2_val = .\psql.exe -c $json_data.query2 -U $config.pguser -d $json_data.database2 -t -A }
       
       if ("lag_is_diff" -in $json_data.PSobject.Properties.Name) { $lag = [Math]::Abs($query2_val-$query1_val) }
       else { $lag = $query2_val }
       $results = @( @{dashboard = $json_data.dashboard; value = [long]$query1_val;lag =[long]$lag}  )
       $results

}  | ConvertTo-Json -Compress


