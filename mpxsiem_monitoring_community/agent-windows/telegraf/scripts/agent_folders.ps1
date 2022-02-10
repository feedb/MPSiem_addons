$ErrorActionPreference = "SilentlyContinue"
$current_folder = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)

if (-not (Test-Path "$current_folder\scripts.conf" -PathType Leaf)) {
     Write-Host "`nERROR: file scripts.conf not found in ""$current_folder"""
      exit(1)
      }

$config = (get-content "$current_folder\scripts.conf" | ConvertFrom-Json )

#из-за проблем\глюков с pipe пришлось разделить на формирование масcива и его заполнение
$folders=@()
foreach ($folder in $config.folders_size) 
 {
  if (Test-Path "$folder" -PathType Container) 
  {
   $size = (Get-ChildItem $folder -Recurse | Measure-Object -Property Length -sum).sum
   if (-not $size) {$size = 0}
   $folders += $folder | Select -Property @{n='dir_path';e={[string]$_}}, @{n='dir_size_bytes';e={[long]$size}}
   }
}

$folders | ConvertTo-Json
