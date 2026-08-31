@echo off
chcp 65001 >nul
title GitHub Auto Push - check-file
cls
echo ======================================================
echo           GITHUB AUTO PUSH - CHECK-FILE
echo ======================================================
echo Repository: https://github.com/hongquang699/check-file
echo.

set /p msg="Nhap commit message (de trong de tu dong dat ten): "

if "%msg%"=="" (
    python github_service.py
) else (
    python github_service.py "%msg%"
)

echo.
echo ======================================================
echo Nhan phim bat ky de thoat...
pause >nul
