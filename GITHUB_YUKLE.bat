@echo off
chcp 65001 >nul
title 💎 SAFIRGUARD - GITHUB'A YUKLE
cd /d "%~dp0"

echo =========================================================
echo 💎 SAFIRGUARD - GITHUB REPO GUNCELLEME VE YUKLEME ARACI
echo Geliştirici: Cebrail Kara (SafirSuite / Benim Yaverim)
echo Web: https://www.safirsuite.com.tr
echo E-Posta: info@safirsuite.com.tr - info@benimyaverim.com.tr
echo =========================================================
echo.

if not exist ".git" (
    echo [1/4] Git deposu baslatiliyor...
    git init
    git branch -M main
) else (
    echo [1/4] Git deposu mevcut...
)

echo [2/4] Tum dosyalar git'e ekleniyor...
git add .

echo [3/4] Commit olusturuluyor...
git commit -m "SafirGuard v1.0 - All-in-One Antivirus & Cyber Threat Defense Suite (Cebrail Kara)"

echo [4/4] GitHub durum kontrolu...
git status

echo.
echo =========================================================
echo [BILGI] Uzak depoya yuklemek icin 'git remote add origin <URL>'
echo ve ardindan 'git push -u origin main' komutunu calistirabilirsiniz.
echo =========================================================
pause
