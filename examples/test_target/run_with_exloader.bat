@echo off
echo Running Test Target with ExLoader...
echo.

REM Build paths
set TARGET_EXE=build\test_target.exe
set EXLOADER_EXE=..\..\build-mingw\exloader.exe
set PROFILE=..\..\profiles\templates\default.json
set LOG_FILE=..\..\logs\test_target_run.jsonl

REM Check if test target exists
if not exist %TARGET_EXE% (
    echo Error: Test target not found!
    echo Please run build.bat first.
    pause
    exit /b 1
)

REM Check if exloader exists
if not exist %EXLOADER_EXE% (
    echo Error: ExLoader not found!
    echo Please build ExLoader first.
    pause
    exit /b 1
)

REM Run ExLoader with test target
echo Starting ExLoader...
echo Target: %TARGET_EXE%
echo Profile: %PROFILE%
echo Log: %LOG_FILE%
echo.

%EXLOADER_EXE% --target %TARGET_EXE% --profile %PROFILE% --log %LOG_FILE%

echo.
echo ExLoader finished. Check %LOG_FILE% for results.
pause
