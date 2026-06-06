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
set "DEINF_BIN=%ROOT%\src\PSHomeDEINF2.0\bin\%CFG%\%TFM%"

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

if not exist "%DEINF_BIN%" (
    echo DEINF build output folder not found:
    echo %DEINF_BIN%
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

echo Copying DEINF output...
xcopy "%DEINF_BIN%\*" "%OUTROOT%\" /e /i /y >nul
if errorlevel 1 (
    echo Failed copying DEINF output.
    pause
    exit /b 1
)

echo.
echo Done.
echo.

IF EXIST "%ROOT%\src\build" ROBOCOPY "%ROOT%\src\build" "%ROOT%" /S /MOVE /XF *.pdb >NUL
IF EXIST "%ROOT%\src\build" RMDIR /S /Q "%ROOT%\src\build"

IF EXIST "%ROOT%\src\PSHomeCryptoTool\bin" RMDIR /S /Q "%ROOT%\src\PSHomeCryptoTool\bin"
IF EXIST "%ROOT%\src\PSHomeCryptoTool\obj" RMDIR /S /Q "%ROOT%\src\PSHomeCryptoTool\obj"

IF EXIST "%ROOT%\src\PSHomeCryptoEncrypt\bin" RMDIR /S /Q "%ROOT%\src\PSHomeCryptoEncrypt\bin"
IF EXIST "%ROOT%\src\PSHomeCryptoEncrypt\obj" RMDIR /S /Q "%ROOT%\src\PSHomeCryptoEncrypt\obj"

IF EXIST "%ROOT%\src\PSHomeCryptoBruteforce\bin" RMDIR /S /Q "%ROOT%\src\PSHomeCryptoBruteforce\bin"
IF EXIST "%ROOT%\src\PSHomeCryptoBruteforce\obj" RMDIR /S /Q "%ROOT%\src\PSHomeCryptoBruteforce\obj"

IF EXIST "%ROOT%\src\PSHomeDEINF2.0\bin" RMDIR /S /Q "%ROOT%\src\PSHomeDEINF2.0\bin"
IF EXIST "%ROOT%\src\PSHomeDEINF2.0\obj" RMDIR /S /Q "%ROOT%\src\PSHomeDEINF2.0\obj"

:END

cmd /k