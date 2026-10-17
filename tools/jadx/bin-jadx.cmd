@echo off
set "TOOLS_DIR=%~dp0"
set "JAVA_HOME=%TOOLS_DIR%runtime\windows-x64"
set "PATH=%JAVA_HOME%\bin;%PATH%"
call "%TOOLS_DIR%app\bin\jadx.bat" %*
