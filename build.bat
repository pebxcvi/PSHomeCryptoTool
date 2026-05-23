@echo off
setlocal

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "SLN=%ROOT%\src\PSHomeCryptoTool.sln"
set "OUTROOT=%ROOT%\src\build"

set "CFG=Release"
set "TFM=net6.0"

set "ENC_BIN=%ROOT%\src\PSHomeCryptoEncrypt\bin\%CFG%\%TFM%"
set "BRUTE_BIN=%ROOT%\src\PSHomeCryptoBruteforce\bin\%CFG%\%TFM%"

echo Checking for .NET 6 SDK...
dotnet --list-sdks | findstr /B /C:"6." >nul
if errorlevel 1 (
    echo .NET 6 SDK not found.
    start https://dotnet.microsoft.com/en-us/download/dotnet/6.0
    pause
    exit /b 1
)

if not exist "%SLN%" (
    echo Solution file not found:
    echo %SLN%
    pause
    exit /b 1
)

echo.
echo Cleaning solution...
dotnet clean "%SLN%" -c %CFG%
if errorlevel 1 (
    echo Clean failed.
    pause
    exit /b 1
)

echo.
echo Building solution...
dotnet build "%SLN%" -c %CFG%
if errorlevel 1 (
    echo Build failed.
    pause
    exit /b 1
)

echo.
echo Preparing output folder...
if exist "%OUTROOT%" rmdir /s /q "%OUTROOT%"
mkdir "%OUTROOT%"

if not exist "%ENC_BIN%" (
    echo Encrypt build output folder not found:
    echo %ENC_BIN%
    pause
    exit /b 1
)

if not exist "%BRUTE_BIN%" (
    echo Bruteforce build output folder not found:
    echo %BRUTE_BIN%
    pause
    exit /b 1
)

echo.
echo Copying Encrypt output...
xcopy "%ENC_BIN%\*" "%OUTROOT%\" /e /i /y >nul
if errorlevel 1 (
    echo Failed copying Encrypt output.
    pause
    exit /b 1
)

echo Copying Bruteforce output...
xcopy "%BRUTE_BIN%\*" "%OUTROOT%\" /e /i /y >nul
if errorlevel 1 (
    echo Failed copying Bruteforce output.
    pause
    exit /b 1
)

echo.
echo Done.
echo.

IF EXIST "%ROOT%\src\build" ROBOCOPY "%ROOT%\src\build" "%ROOT%" /S /MOVE /XF *.pdb >NUL
IF EXIST "%ROOT%\src\build" RMDIR /S /Q "%ROOT%\src\build"

:END

cmd /k