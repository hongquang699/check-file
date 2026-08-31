@echo off
chcp 65001 >nul
title Virus & Hidden Files / Folders Scanner
cls
echo ======================================================================
echo             VIRUS & HIDDEN FILES / FOLDERS SCANNER
echo ======================================================================
echo.
echo Dan link URL hoac duong dan File / Thu muc can kiem tra vao day:
echo (Hoac nhan Enter de vao Menu tuy chon)
echo.
set /p target="> "

if "%target%"=="" (
    python main.py
) else (
    python main.py "%target%"
    echo.
    echo ======================================================================
    echo Nhan phim bat ky de tiep tuc...
    pause >nul
)
