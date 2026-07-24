$svcName = "TestSvc45"
$exePath = "C:\Program Files\Blackshard\blackshard-service.exe"
New-Service -Name $svcName -BinaryPathName "C:\temp.exe" | Out-Null
$binPath = "`"$exePath`" --service"
& sc.exe config $svcName binPath= $binPath | Out-Null
$outPath = Join-Path $PSScriptRoot "temp_svc45.txt"
& sc.exe qc $svcName | Out-File $outPath
# Remove-Service $svcName
