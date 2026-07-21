#Requires -RunAsAdministrator
[CmdletBinding()]
param()

& (Join-Path $PSScriptRoot "install.ps1") -Uninstall
exit $LASTEXITCODE
