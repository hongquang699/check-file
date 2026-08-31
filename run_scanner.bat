@echo off
chcp 65001 >nul
title Virus & Hidden Files / Folders Scanner
cls
echo ======================================================================
echo             VIRUS & HIDDEN FILES / FOLDERS SCANNER
echo ======================================================================
echo.
echo Paste download URL or local File / Directory path to scan:
echo (Or press Enter to open the interactive menu)
echo.
set /p target="> "

if "%target%"=="" (
    python main.py
) else (
    python main.py "%target%"
    echo.
    echo ======================================================================
    echo Press any key to continue...
    pause >nul
)
