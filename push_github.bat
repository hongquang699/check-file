@echo off
chcp 65001 >nul
title GitHub Auto Push - check-file
cls
echo ======================================================
echo           GITHUB AUTO PUSH - CHECK-FILE
echo ======================================================
echo Repository: https://github.com/hongquang699/check-file
echo.

set /p msg="Enter commit message (press Enter for auto timestamp): "

if "%msg%"=="" (
    python github_service.py
) else (
    python github_service.py "%msg%"
)

echo.
echo ======================================================
echo Press any key to exit...
pause >nul
