@echo off
chcp 65001 >nul
title 💎 SafirGuard Siber Savunma ve Antivirüs (WPF Desktop Suite)
cd /d "%~dp0"

echo ========================================================
echo   💎 SAFIRGUARD SİBER SAVUNMA VE ANTİVİRÜS SİSTEMİ
echo   🛡️ Native Masaüstü Programı Başlatılıyor...
echo   👨‍💻 Geliştirici: Cebrail Kara (SafirSuite)
echo ========================================================
echo.

if exist "%~dp0publish\SafirGuard.App.exe" (
    echo [+] SafirGuard Native Masaüstü Programı Başlatılıyor...
    start "" "%~dp0publish\SafirGuard.App.exe"
) else if exist "%~dp0Portable\SafirGuard.App.exe" (
    echo [+] Portable Sürüm Başlatılıyor...
    start "" "%~dp0Portable\SafirGuard.App.exe"
) else if exist "%~dp0Release\SafirGuard.App.exe" (
    echo [+] Release Sürüm Başlatılıyor...
    start "" "%~dp0Release\SafirGuard.App.exe"
) else (
    echo [*] Kaynak kod üzerinden başlatılıyor (dotnet run)...
    cd SafirGuard_CSharp\src\SafirGuard.App
    dotnet run -c Release
)
