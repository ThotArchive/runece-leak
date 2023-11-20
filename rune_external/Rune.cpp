//
// Created by Dottik on 19/11/2023.
//
#include <optional>
#include "Rune.hpp"

#include <cstdint>
#include <fstream>
#include <iostream>
#include "oxorany.hpp"
#include "Utilities.hpp"
#include "LogInterceptor.hpp"

const char *Rune::ReadString(std::uintptr_t address, int suspectedSize) {
    char s_buffer = oxorany('A');
    DWORD str_length = 0;

    while (oxorany('\0') != s_buffer && suspectedSize >= str_length) {
        if (false ==
            ReadProcessMemory(this->m_hRobloxProcess, reinterpret_cast<LPCVOID>(address + (str_length * sizeof(char))),
                              &s_buffer, 1, nullptr)) {
            // TODO: Failure, handle failure.
            // std::cerr << "Fuck " << GetLastError() << std::endl;
            if (GetLastError() == ERROR_NOACCESS) {
                return "NO_ACCESS"; // Mem location ain't valid.
            }
        }
        str_length++;
        // Get the size of the string (Until we hit the null byte)
    }

    // Get string.
    char *buf = new char[str_length];

    if (false ==
        ReadProcessMemory(this->m_hRobloxProcess, reinterpret_cast<LPCVOID>(address), buf, str_length, nullptr)) {
        // TODO: Failure, handle failure.

    }

    return buf;
}

BYTE Rune::ReadByte(std::uintptr_t address) {
    BYTE buf = {};
    auto dwSize = oxorany(sizeof(BYTE));
    if (false ==
        ReadProcessMemory(this->m_hRobloxProcess, reinterpret_cast<LPCVOID>(address), &buf, dwSize, nullptr)) {
        // TODO: Failure, handle failure.
    }
    return buf;
}

WORD Rune::ReadWord(std::uintptr_t address) {
    WORD buf = {};
    auto dwSize = oxorany(sizeof(WORD));
    if (false ==
        ReadProcessMemory(this->m_hRobloxProcess, reinterpret_cast<LPCVOID>(address), &buf, dwSize, nullptr)) {
        // TODO: Failure, handle failure.
    }
    return buf;
}

DWORD Rune::ReadDword(std::uintptr_t address) {
    DWORD buf = {};
    auto dwSize = oxorany(sizeof(DWORD));
    if (false ==
        ReadProcessMemory(this->m_hRobloxProcess, reinterpret_cast<LPCVOID>(address), &buf, dwSize, nullptr)) {
        // TODO: Failure, handle failure.
    }
    return buf;
}

DWORD64 Rune::ReadQword(std::uintptr_t address) {
    SIZE_T readMemory = 0;
    DWORD64 buf = {};
    auto dwSize = oxorany(sizeof(DWORD64));
    if (false ==
        ReadProcessMemory(this->m_hRobloxProcess, reinterpret_cast<LPCVOID>(address), &buf, dwSize, &readMemory)) {
        // TODO: Failure, handle failure.
        // std::cerr << "The fuck " << GetLastError() << std::endl;
    }
    return buf;
}

DWORD64 Rune::ReadDword64(std::uintptr_t address) {
    return this->ReadQword(address);
}

void Rune::Initialise() {
    // TODO: Write.
    this->m_dwRobloxPid = Utilities::FindProcessId(oxorany(L"RobloxPlayerBeta.exe"));
    this->m_hRobloxProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                                         PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                         PROCESS_SUSPEND_RESUME, false,
                                         this->m_dwRobloxPid);

}

Rune::Rune() {
    this->m_hRobloxProcess = nullptr;
    this->m_pDataModel = 0;
    this->m_dwRobloxPid = 0;
}

DWORD64 Rune::GetLocalPlayer(DWORD64 playerServiceAddress) {
    return this->ReadQword(playerServiceAddress + oxorany(0x240));
}

std::uintptr_t Rune::GetDataModel() {
    if (this->m_pDataModel != 0) return this->m_pDataModel;
    auto latestLog = LogInterceptor::GetLastestLog();

    std::ifstream robloxLog(latestLog);

    std::string rbxLogLine{};
    while (this->m_pDataModel == 0) {
        std::getline(robloxLog, rbxLogLine);

        if (rbxLogLine.contains("initialized DataModel(")) {
            // DataModel address.
            rbxLogLine = rbxLogLine.substr(rbxLogLine.find("initialized DataModel(") + 22);
            rbxLogLine = rbxLogLine.substr(0, rbxLogLine.find(')'));
            auto address = std::strtoull(rbxLogLine.c_str(), nullptr, 16);
            this->m_pDataModel = address;
        }
    }

    return this->m_pDataModel;
}

[[maybe_unused]] HANDLE Rune::GetRobloxHandle() {
    return this->m_hRobloxProcess;
}


