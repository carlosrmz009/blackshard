$svcName = "TestSvc80"
$exePath = "C:\Program Files\Blackshard\blackshard.exe"
$serviceCommand = "`"$exePath`" --service"

Write-Host "Creating service..."
New-Service -Name $svcName -BinaryPathName $exePath -StartupType Automatic | Out-Null
Write-Host "Service created. Current ImagePath:"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath | Select-Object -ExpandProperty ImagePath

Write-Host "Updating ImagePath..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath -Value $serviceCommand -Type ExpandString

Write-Host "Updated ImagePath:"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath | Select-Object -ExpandProperty ImagePath

Write-Host "SC QC output:"
& sc.exe qc $svcName

Remove-Service $svcName
Write-Host "Done."
