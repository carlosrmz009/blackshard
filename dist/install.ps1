$DriverName = "blackshard"
$SysPath = "$PSScriptRoot\blackshard.sys"
$DestPath = "$env:SystemRoot\System32\drivers\blackshard.sys"
sc.exe stop $DriverName
sc.exe delete $DriverName
Start-Sleep -Seconds 1
Copy-Item -Path $SysPath -Destination $DestPath -Force
sc.exe create $DriverName type= filesys start= demand error= normal binPath= "System32\drivers\blackshard.sys" group= "FSFilter Anti-Virus" depend= FltMgr
$RegBase = "HKLM:\System\CurrentControlSet\Services\$DriverName"
New-ItemProperty -Path $RegBase -Name "DebugFlags" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path $RegBase -Name "SupportedFeatures" -Value 3 -PropertyType DWord -Force
$InstancesPath = "$RegBase\Instances"
New-Item -Path $InstancesPath -Force
New-ItemProperty -Path $InstancesPath -Name "DefaultInstance" -Value "blackshard Instance" -PropertyType String -Force
$InstancePath = "$InstancesPath\blackshard Instance"
New-Item -Path $InstancePath -Force
New-ItemProperty -Path $InstancePath -Name "Altitude" -Value "328000" -PropertyType String -Force
New-ItemProperty -Path $InstancePath -Name "Flags" -Value 0 -PropertyType DWord -Force
Write-Host "fltmc load blackshard" -ForegroundColor Green
