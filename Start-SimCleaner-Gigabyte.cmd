@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -File "%~dp0Launch-SimCleaner.ps1" -Script SimCleaner.ps1 -ExpectedDevice Gigabyte %*
set "inspection_exit=%errorlevel%"
pause
exit /b %inspection_exit%
