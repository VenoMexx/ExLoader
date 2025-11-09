@echo off
setlocal

set "ROOT_DIR=%~dp0.."
set "BUILD_DIR=%ROOT_DIR%\build-mingw32"
set "EXLOADER=%BUILD_DIR%\exloader.exe"
set "TEST_TARGET=%BUILD_DIR%\examples\test_target_build\test_target.exe"
set "PROFILE=%ROOT_DIR%\profiles\templates\default.json"
set "LOG_FILE=%ROOT_DIR%\logs\test_run_32bit.jsonl"

echo ========================================
echo ExLoader 32-bit Test
echo ========================================
echo.

if not exist "%EXLOADER%" (
    echo ERROR: ExLoader not found at %EXLOADER%
    echo Please run build_all.bat first.
    pause
    exit /b 1
)

if not exist "%TEST_TARGET%" (
    echo ERROR: Test target not found at %TEST_TARGET%
    echo Please run build_all.bat first.
    pause
    exit /b 1
)

echo [1] Testing ExLoader 32-bit...
"%EXLOADER%" --help
if errorlevel 1 (
    echo ERROR: ExLoader failed to start
    pause
    exit /b 1
)

echo.
echo [2] Testing standalone target (no hooks)...
"%TEST_TARGET%"
echo.

echo [3] Testing ExLoader with hooks...
echo Target: %TEST_TARGET%
echo Profile: %PROFILE%
echo Log: %LOG_FILE%
echo.

"%EXLOADER%" --target "%TEST_TARGET%" --profile "%PROFILE%" --log "%LOG_FILE%"

echo.
echo ========================================
echo Test completed! Check %LOG_FILE%
echo ========================================
pause
