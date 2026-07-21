New-Item -ItemType Directory -Force -Path "dist"

if (Test-Path "src\driver\blackshard.inf") {
    Copy-Item -Path "src\driver\blackshard.inf" -Destination "dist\blackshard.inf" -Force
}

if (Test-Path "src\driver\x64\Release\blackshard.sys") {
    Copy-Item -Path "src\driver\x64\Release\blackshard.sys" -Destination "dist\blackshard.sys" -Force
} else {
    Write-Host "[!] Warning: src\driver\x64\Release\blackshard.sys not found. Compile the driver with Visual Studio + WDK first." -ForegroundColor Yellow
}

if (Get-Command cargo -ErrorAction SilentlyContinue) {
    cargo build --release
    if (Test-Path "target\release\blackshard.exe") {
        Copy-Item -Path "target\release\blackshard.exe" -Destination "dist\blackshard.exe" -Force
    }
} else {
    Write-Host "[!] Error: 'cargo' is not installed or not in PATH. Please install Rust (rustup.rs)." -ForegroundColor Red
}
