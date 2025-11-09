@echo off
echo Building ExLoader Test Target...
echo.

if not exist build mkdir build
cd build

cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 (
    echo CMake configuration failed!
    pause
    exit /b 1
)

cmake --build .
if errorlevel 1 (
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo Build successful! Executable: build\test_target.exe
echo.
pause
