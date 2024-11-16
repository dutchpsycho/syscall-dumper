#include <Windows.h>

#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <optional>
#include <format>
#include <unordered_map>

template <typename T>
constexpr T resolve_rva(const void* base, DWORD rva) noexcept {
    return reinterpret_cast<T>(reinterpret_cast<const BYTE*>(base) + rva);
}

[[nodiscard]] std::optional<BYTE*> funcAddr(const HMODULE module, const std::string_view func_name) noexcept {
    auto* func_addr = reinterpret_cast<BYTE*>(GetProcAddress(module, func_name.data()));
    return func_addr ? std::make_optional(func_addr) : std::nullopt;
}

[[nodiscard]] constexpr bool isSyscall(const BYTE* bytes, const size_t actual_size = 8) noexcept {
    return (actual_size >= 8 &&
            bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && // mov r10, rcx
            bytes[3] == 0xB8);                                          // mov eax, <callnum>
}

[[nodiscard]] constexpr bool VStub(const BYTE* bytes, const size_t max_search_len = 32) noexcept {
    if (!isSyscall(bytes)) [[unlikely]] {
        return false;
    }
    for (size_t i = 4; i < max_search_len - 2; ++i) {
        if (bytes[i] == 0x0F && bytes[i + 1] == 0x05 && bytes[i + 2] == 0xC3) { // syscall; ret
            return true;
        }
    }
    return false;
}

[[nodiscard]] constexpr std::optional<DWORD> XtractNum(const BYTE* bytes) noexcept {
    return (isSyscall(bytes) && VStub(bytes)) ? std::make_optional(*reinterpret_cast<const DWORD*>(bytes + 4))
                                              : std::nullopt;
}

std::string get_windows_version() noexcept {
    RTL_OSVERSIONINFOW version_info = { sizeof(RTL_OSVERSIONINFOW) };
    const auto rtl_get_version = reinterpret_cast<NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));

    if (rtl_get_version && rtl_get_version(&version_info) == 0) {
        return std::format("==== {}.{} Build {} ====\n\n", 
                           version_info.dwMajorVersion, 
                           version_info.dwMinorVersion, 
                           version_info.dwBuildNumber);
    }
    return "==== Unknown Windows Version ====\n\n";
}

void dump(const std::string_view module_name, const std::string_view prefix, const std::string& output_file, bool resolve_syscalls) noexcept {
    const auto module = LoadLibraryExW(std::wstring(module_name.begin(), module_name.end()).c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!module) [[unlikely]] {
        std::cerr << "failed to load " << module_name << "\n";
        return;
    }

    const auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    const auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const BYTE*>(module) + dos_header->e_lfanew);

    const auto export_dir_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const auto export_dir = resolve_rva<const IMAGE_EXPORT_DIRECTORY*>(module, export_dir_rva);
    const auto name_rvas = resolve_rva<const DWORD*>(module, export_dir->AddressOfNames);
    const auto func_rvas = resolve_rva<const DWORD*>(module, export_dir->AddressOfFunctions);
    const auto name_ordinals = resolve_rva<const WORD*>(module, export_dir->AddressOfNameOrdinals);

    std::ofstream output(output_file, std::ios::out);
    if (!output.is_open()) [[unlikely]] {
        std::cerr << "failed to open " << output_file << "\n";
        FreeLibrary(module);
        return;
    }

    output << get_windows_version();

    for (size_t i = 0; i < export_dir->NumberOfNames; ++i) {
        const auto func_name = resolve_rva<const char*>(module, name_rvas[i]);

        if (std::string_view(func_name).starts_with(prefix)) {
            const auto func_rva = func_rvas[name_ordinals[i]];
            const auto func_addr = resolve_rva<const void*>(module, func_rva);

            if (resolve_syscalls) {
                const auto func_bytes = funcAddr(module, func_name);
                if (func_bytes) {
                    const auto syscall_num = XtractNum(func_bytes.value());
                    if (syscall_num) {
                        std::cout << func_name << " :: " << std::hex << syscall_num.value() << "\n";
                        output << func_name << " :: " << std::hex << syscall_num.value() << "\n";
                    }
                }
            } else {
                std::cout << func_name << " :: " << func_addr << "\n";
                output << func_name << " :: " << func_addr << "\n";
            }
        }
    }

    FreeLibrary(module);
}

int main() noexcept {
    std::cout << "made by hatedamon\n";

    dump("ntoskrnl.exe", "Ke", "KeAddr.dat", false);
    dump("ntdll.dll", "Nt", "NtCalls.dat", true);
    dump("ntdll.dll", "Zw", "ZwCalls.dat", true);

    std::cout << "\ndone :3";
    std::cin.get();

    return 0;
}