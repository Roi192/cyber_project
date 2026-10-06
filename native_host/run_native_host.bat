@echo off
REM Step 24A: launched by Chrome/Edge via the native messaging host
REM registration - never run directly. %~dp0 resolves to this file's own
REM directory regardless of the browser's current working directory.
"%~dp0..\venv\Scripts\python.exe" "%~dp0..\browser_native_host.py"
