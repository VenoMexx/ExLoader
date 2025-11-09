@echo off
setlocal enabledelayedexpansion

set "ROOT_DIR=%~dp0.."
set "BUILD32=%ROOT_DIR%\build-mingw32"

set "DEFAULT_MINGW32=C:\msys64\mingw32"

if not defined MINGW32_PREFIX set "MINGW32_PREFIX=%DEFAULT_MINGW32%"

set "ORIG_PATH=%PATH%"
set "CMAKE_CMD=cmake"

call :build_arch "MinGW32" "%MINGW32_PREFIX%" "%BUILD32%" "%ROOT_DIR%\cmake\toolchains\mingw32-toolchain.cmake" || goto :error

echo [*] MinGW32 binaries located at %BUILD32%
echo Success!
exit /b 0

:build_arch
set "ARCH_NAME=%~1"
set "TOOLCHAIN_ROOT=%~2"
set "BUILD_DIR=%~3"
set "TOOLCHAIN_FILE=%~4"

if not exist "%TOOLCHAIN_ROOT%\bin\gcc.exe" (
    echo [%ARCH_NAME%] ERROR: gcc.exe not found under "%TOOLCHAIN_ROOT%\bin".
    exit /b 1
)

echo [Config] %ARCH_NAME% using toolchain root %TOOLCHAIN_ROOT%
set "PATH=%TOOLCHAIN_ROOT%\bin;%ORIG_PATH%"

%CMAKE_CMD% -S "%ROOT_DIR%" -B "%BUILD_DIR%" -G "MinGW Makefiles" ^
  -DCMAKE_TOOLCHAIN_FILE="%TOOLCHAIN_FILE%" || exit /b 1

echo [Build ] %ARCH_NAME%
%CMAKE_CMD% --build "%BUILD_DIR%" || exit /b 1

set "PATH=%ORIG_PATH%"
exit /b 0

:error
echo Build failed with error %errorlevel%.
exit /b %errorlevel%
