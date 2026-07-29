$svcName = "TestSvc60"
$exePath = "C:\Program Files\blackshard\blackshard-service.exe"


$serviceCommand = "`"$exePath`" --service"
New-Service -Name $svcName -BinaryPathName $serviceCommand -StartupType Automatic | Out-Null
$v1 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath).ImagePath
Remove-Service $svcName


New-Service -Name $svcName -BinaryPathName $exePath -StartupType Automatic | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath -Value "`"$exePath`" --service" -Type ExpandString
$v2 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath).ImagePath
Remove-Service $svcName


& cmd.exe /c ("sc.exe create {0} binPath= `"`"{1}`" --service`" type= own start= auto" -f $svcName, $exePath) | Out-Null
$v3 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath).ImagePath
& sc.exe delete $svcName | Out-Null

$results = @"
v1: $v1
v2: $v2
v3: $v3
"@
$results | Out-File (Join-Path $PSScriptRoot "test_results.txt") -Encoding utf8
