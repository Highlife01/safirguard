@echo off
chcp 65001 >nul
title 💎 SafirGuard - Tum Guvenlik Testlerini Calistir
cd /d "%~dp0"

echo ========================================================
echo   💎 SAFIRGUARD TUM BIRIM VE GUVENLIK TESTLERI
echo   👨‍💻 Gelistirici: Cebrail Kara (SafirSuite)
echo ========================================================
echo.

echo ========================================================
echo   [1] C# .NET 8 GUVENLIK MOTORLARI TESTI (xUnit)
echo ========================================================
dotnet test "SafirGuard_CSharp\SafirGuard.slnx"

echo.
echo ========================================================
echo   [2] PYTHON SEZGISEL VE IMZA TESTLERI (unittest)
echo ========================================================
python -m unittest discover -s "SafirGuard_Python\tests" -p "test_*.py"

echo.
echo ========================================================
echo   Test Islemi Tamamlandi!
echo ========================================================
pause
