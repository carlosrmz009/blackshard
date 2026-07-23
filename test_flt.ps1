Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class FltMgr {
    [DllImport("fltlib.dll", CharSet=CharSet.Unicode)]
    public static extern int FilterConnectCommunicationPort(string lpPortName, uint dwOptions, IntPtr lpContext, ushort wSizeOfContext, IntPtr lpSecurityAttributes, out IntPtr hPort);
}
"@

$port = [IntPtr]::Zero
$hr = [FltMgr]::FilterConnectCommunicationPort("\BlackshardPort", 0, [IntPtr]::Zero, 0, [IntPtr]::Zero, [ref]$port)
Write-Host "HRESULT: 0x$($hr.ToString('X8'))"
