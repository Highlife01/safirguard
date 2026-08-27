@echo off
chcp 65001 >nul
title 💎 SafirGuard - Derleme ve Paketleme Aracı
cd /d "%~dp0"

echo ========================================================
echo   💎 SAFIRGUARD DÜNYA STANDARTLARINDA DERLEME VE YAYIN
echo   👨‍💻 Geliştirici: Cebrail Kara (SafirSuite)
echo ========================================================
echo.

echo [1/4] .NET Testleri Calistiriliyor...
dotnet test "SafirGuard_CSharp\SafirGuard.slnx"
if %ERRORLEVEL% NEQ 0 (
    echo [HATA] .NET Testleri basarisiz oldu!
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [2/4] C# Single-File Release EXE Derleniyor...
dotnet publish "SafirGuard_CSharp\src\SafirGuard.App\SafirGuard.App.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o "Release"

if exist "Release\SafirGuard.App.exe" (
    copy /Y "Release\SafirGuard.App.exe" "Release\SafirGuard.exe" >nul
)

echo.
echo [3/4] C# Portable Surum Derleniyor...
dotnet publish "SafirGuard_CSharp\src\SafirGuard.App\SafirGuard.App.csproj" -c Release -r win-x64 --self-contained true -o "Portable"

echo.
echo [4/4] Dağıtım ZIP Arşivi Paketleniyor...
powershell -Command "if (Test-Path 'Release\SafirGuard-v1.0-Windows-x64.zip') { Remove-Item 'Release\SafirGuard-v1.0-Windows-x64.zip' -Force }; Compress-Archive -Path 'Release\SafirGuard.exe', 'Release\SafirGuard_Baslat.bat', 'Release\appsettings.json', 'Release\wwwroot' -DestinationPath 'Release\SafirGuard-v1.0-Windows-x64.zip' -Force"

echo.
echo ========================================================
echo   [BASARILI] SafirGuard tum surumleriyle derlendi!
echo   📁 Release: SafirGuard\Release\SafirGuard.exe
echo   📁 Portable: SafirGuard\Portable\SafirGuard.App.exe
echo   📦 ZIP Arşivi: SafirGuard\Release\SafirGuard-v1.0-Windows-x64.zip
echo ========================================================
pause
