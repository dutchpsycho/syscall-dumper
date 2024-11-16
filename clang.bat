@echo off

echo compiling... (dumper.cc -o dumper.exe -std=c++20 -target x86_64-windows -fuse-ld=lld -luser32 -lkernel32)

clang++ dumper.cc -o dumper.exe -std=c++20 -target x86_64-windows -fuse-ld=lld -luser32 -lkernel32

if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo done.