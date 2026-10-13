@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -File "%~dp0Launch-SimCleaner.ps1" -Script Inspect-Windows.ps1 -ExpectedDevice Victus %*
set "inspection_exit=%errorlevel%"
pause
exit /b %inspection_exit%
