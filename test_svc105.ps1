$svcName = "TestSvc105"
$exePath = "C:\Program Files\Blackshard\blackshard.exe"
$serviceCommand = "`"$exePath`" --service"
New-Service -Name $svcName -BinaryPathName "C:\dummy.exe" -StartupType Automatic | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath -Value $serviceCommand -Type ExpandString
$val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath).ImagePath
$val | Out-File (Join-Path $PSScriptRoot "test_svc_105_out.txt")
Remove-Service $svcName
