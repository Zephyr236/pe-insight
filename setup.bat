@echo off
REM 双击即可安装 PE Insight
REM 传参示例：setup.bat -SkipTools
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
if errorlevel 1 pause
