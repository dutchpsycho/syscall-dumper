@echo off

if not exist ".\exe" mkdir .\exe

echo if this doesn't work, u don't have Visual Studio tools installed
echo if it shows "system cannot find path", it compiled, it's in /exe.
echo. 

cmake -G "Visual Studio 17 2022" -A x64 -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

move /Y build\dumper.exe .\exe\ >nul 2>&1
if exist build\Release\dumper.exe (
    move /Y build\Release\dumper.exe .\exe\ >nul 2>&1
)

rd /s /q build >nul 2>&1

echo compilation done. exe is in -> .\exe\