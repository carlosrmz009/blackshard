@echo off
setlocal

echo [*] Compiling Blackshard Driver using EWDK environment...

:: Ensure output directory exists
mkdir src\driver\x64\Release 2>nul

:: Explicitly define the Kernel Mode include paths using EWDK environment variables
set "INC_KM=%WindowsSdkDir%Include%WindowsSDKVersion%km"
set "INC_CRT=%WindowsSdkDir%Include%WindowsSDKVersion%km\crt"
set "INC_SHARED=%WindowsSdkDir%Include%WindowsSDKVersion%shared"
set "LIB_KM=%WindowsSdkDir%Lib%WindowsSDKVersion%km\x64"

echo [*] Compiling blackshard_driver.c...
cl /nologo /c /O2 /W3 /GS- /D AMD64 /D _KERNEL_MODE /I "%INC_KM%" /I "%INC_CRT%" /I "%INC_SHARED%" src\driver\blackshard_driver.c /Fo:src\driver\x64\Release\blackshard_driver.obj

if %ERRORLEVEL% NEQ 0 (
echo [!] Compilation failed. Make sure you are running this inside the EWDK prompt!
exit /b %ERRORLEVEL%
)

:: Link the driver
echo [*] Linking blackshard.sys...
link /nologo /MACHINE:X64 /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /LIBPATH:"%LIB_KM%" fltMgr.lib ntoskrnl.lib hal.lib src\driver\x64\Release\blackshard_driver.obj /OUT:src\driver\x64\Release\blackshard.sys

if %ERRORLEVEL% NEQ 0 (
echo [!] Linking failed.
exit /b %ERRORLEVEL%
)

echo [+] SUCCESS: src\driver\x64\Release\blackshard.sys generated.