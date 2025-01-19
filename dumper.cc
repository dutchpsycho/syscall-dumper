#include <Windows.h>

#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <optional>
#include <format>
#include <algorithm>
#include <execution>
#include <stdexcept>
#include <mutex>

template <typename T>
constexpr T resolve_rva(const void* base, DWORD rva) noexcept {
    return reinterpret_cast<T>(reinterpret_cast<const BYTE*>(base) + rva);
}

[[nodiscard]] constexpr bool isValidSyscall(const BYTE* bytes, const size_t actual_size = 8, const size_t max_search_len = 32) noexcept {
    if (actual_size < 8 || bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1 || bytes[3] != 0xB8) {
        return false;
    }
    for (size_t i = 4; i < max_search_len - 2; ++i) {
        if (bytes[i] == 0x0F && bytes[i + 1] == 0x05 && bytes[i + 2] == 0xC3) { // syscall; ret
            return true;
        }
    }
    return false;
}

std::string get_windows_version() noexcept {
    RTL_OSVERSIONINFOW version_info = { sizeof(RTL_OSVERSIONINFOW) };
    const auto rtl_get_version = reinterpret_cast<NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));

    if (rtl_get_version && rtl_get_version(&version_info) == 0) {
        return std::format("==== Windows Version: {}.{} (Build {}) ====\n\n",
                           version_info.dwMajorVersion,
                           version_info.dwMinorVersion,
                           version_info.dwBuildNumber);
    }
    return "==== Unknown Windows Version ====\n\n";
}

class MappedFile {
    HANDLE file_handle = nullptr;
    HANDLE mapping_handle = nullptr;
    void* mapped_view = nullptr;

public:
    explicit MappedFile(const std::wstring& path) {
        file_handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_handle == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Failed to open file: " + std::string(path.begin(), path.end()));
        }

        mapping_handle = CreateFileMappingW(file_handle, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
        if (!mapping_handle) {
            CloseHandle(file_handle);
            throw std::runtime_error("Failed to create file mapping: " + std::string(path.begin(), path.end()));
        }

        mapped_view = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);
        if (!mapped_view) {
            CloseHandle(mapping_handle);
            CloseHandle(file_handle);
            throw std::runtime_error("Failed to map file: " + std::string(path.begin(), path.end()));
        }
    }

    ~MappedFile() {
        if (mapped_view) UnmapViewOfFile(mapped_view);
        if (mapping_handle) CloseHandle(mapping_handle);
        if (file_handle) CloseHandle(file_handle);
    }

    [[nodiscard]] void* get() const noexcept {
        return mapped_view;
    }
};

// dump SSNs from given DLL
std::vector<std::pair<std::string, DWORD>> dump_ssns_from_dll(const std::wstring& dll_path) {
    std::vector<std::pair<std::string, DWORD>> ssn_list;

    MappedFile mapped_file(dll_path);
    void* mapped_dll = mapped_file.get();

    const auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(mapped_dll);
    const auto nt_header = resolve_rva<const IMAGE_NT_HEADERS*>(mapped_dll, dos_header->e_lfanew);
    const auto export_dir_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const auto export_dir = resolve_rva<const IMAGE_EXPORT_DIRECTORY*>(mapped_dll, export_dir_rva);
    const auto exception_dir_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    const auto exception_dir_size = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    const auto exception_dir = resolve_rva<const RUNTIME_FUNCTION*>(mapped_dll, exception_dir_rva);
    const auto name_rvas = resolve_rva<const DWORD*>(mapped_dll, export_dir->AddressOfNames);
    const auto func_rvas = resolve_rva<const DWORD*>(mapped_dll, export_dir->AddressOfFunctions);
    const auto name_ordinals = resolve_rva<const WORD*>(mapped_dll, export_dir->AddressOfNameOrdinals);

    for (size_t i = 0; i < export_dir->NumberOfNames; ++i) {
        const auto func_name = resolve_rva<const char*>(mapped_dll, name_rvas[i]);

        // filter for nt
        if (std::string_view(func_name).starts_with("Nt")) {
            const auto func_rva = func_rvas[name_ordinals[i]];
            const auto func_addr = resolve_rva<const BYTE*>(mapped_dll, func_rva);

            // xref w/ exceptions dir
            bool found_in_exception = false;
            for (size_t j = 0; j < exception_dir_size / sizeof(RUNTIME_FUNCTION); ++j) {
                const auto& runtime_func = exception_dir[j];
                const auto func_start = resolve_rva<const void*>(mapped_dll, runtime_func.BeginAddress);
                if (func_addr == func_start) {
                    found_in_exception = true;
                    break;
                }
            }

            if (found_in_exception && isValidSyscall(func_addr)) {
                const DWORD ssn = *reinterpret_cast<const DWORD*>(func_addr + 4); // SSN is imm32 in eax
                ssn_list.emplace_back(func_name, ssn);
            }
        }
    }

    return ssn_list;
}

void dump_syscalls(const std::vector<std::wstring>& dll_paths, const std::string& output_file) {
    std::vector<std::pair<std::string, DWORD>> all_ssns;
    std::mutex ssn_mutex;

    std::for_each(std::execution::par, dll_paths.begin(), dll_paths.end(), [&](const auto& dll_path) {
        try {
            const auto ssns = dump_ssns_from_dll(dll_path);
            std::scoped_lock lock(ssn_mutex);
            all_ssns.insert(all_ssns.end(), ssns.begin(), ssns.end());
        } catch (const std::exception& ex) {
            std::cerr << "Error processing " << std::string(dll_path.begin(), dll_path.end()) << ": " << ex.what() << "\n";
        }
    });

    std::sort(all_ssns.begin(), all_ssns.end(), [](const auto& a, const auto& b) {
        return a.second < b.second;
    });

    std::ofstream output(output_file, std::ios::out);
    if (!output.is_open()) {
        throw std::runtime_error("Failed to open output file");
    }

    output << get_windows_version();

    for (const auto& [name, ssn] : all_ssns) {
        output << std::format("{}:: 0x{:X} | {}\n", name, ssn, ssn);
    }
}

int main() {
    try {
        std::vector<std::wstring> dlls = {
            L"C:\\Windows\\System32\\ntdll.dll",
            L"C:\\Windows\\System32\\win32u.dll",
            L"C:\\Windows\\System32\\gdi32full.dll",
            L"C:\\Windows\\System32\\kernelbase.dll"
        };

        dump_syscalls(dlls, "syscalls.dat");
        std::cout << "Done.\n";
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << '\n';
    }

    return 0;
}