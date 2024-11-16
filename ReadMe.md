### Syscall Dumper

This project is a simple Windows Util that dumps Nt, Zw & Ke calls relative to your system. (Win10&11)

### Features:
- Dumps Nt & Zw calls & their syscall numbers (undocumented included)
- Dumps Ke (Kernel) mem addresses (cannot be invoked from UM)
- Built using C++20 and can be compiled with either `clang++` or `Visual Studio` tools.

### Output
- NtCalls.dat
- ZwCalls.dat
- KeAddr.dat

### Compilation:
The project can be compiled using either **Visual Studio** (via CMake) or **Clang++**. 

### Steps to Compile:

#### Using Visual Studio (via CMake):
1. Make sure you have **Visual Studio** installed with **C++ tools** and **CMake** support.
2. Run the `compile.bat` script in the terminal:
   - This will auto configure with CMake & output the dumperexe into /exe/
   
#### Using Clang++:
1. Ensure you have **Clang++** installed and properly configured.
2. Run the `compile.bat` script in the terminal:
   - This will output dumper.exe into the root dir

### License:
N/A