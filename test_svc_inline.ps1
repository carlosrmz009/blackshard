$svcName = "TestSvc86"
$exePath = "C:\Program Files\Blackshard\blackshard.exe"
$serviceCommand = "`"$exePath`" --service"
$outPath = Join-Path $PSScriptRoot "test_results.txt"
Remove-Item -Force $outPath -ErrorAction SilentlyContinue

Write-Host "Creating service..." | Out-File $outPath -Append
New-Service -Name $svcName -BinaryPathName $exePath -StartupType Automatic | Out-Null
Write-Host "Service created. Current ImagePath:" | Out-File $outPath -Append
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath | Select-Object -ExpandProperty ImagePath | Out-File $outPath -Append

Write-Host "Updating ImagePath..." | Out-File $outPath -Append
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath -Value $serviceCommand -Type ExpandString

Write-Host "Updated ImagePath:" | Out-File $outPath -Append
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath | Select-Object -ExpandProperty ImagePath | Out-File $outPath -Append

Write-Host "SC QC output:" | Out-File $outPath -Append
& sc.exe qc $svcName | Out-File $outPath -Append

Remove-Service $svcName
Write-Host "Done." | Out-File $outPath -Append
